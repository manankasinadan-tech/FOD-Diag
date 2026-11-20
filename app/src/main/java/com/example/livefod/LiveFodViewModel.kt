package com.example.livefod

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File

data class LiveFodUiState(
    val hud: LiveCaptureHudState = LiveCaptureHudState(),
    val sessions: List<LiveFodSession> = emptyList(),
    val activeSession: LiveFodSession? = null,
    val selectedCompareAId: String? = null,
    val selectedCompareBId: String? = null,
    val comparisonReport: LiveComparisonReport? = null,
    val liveSessionsDirPath: String = "/sdcard/FOD Database/LiveFodSessions",
    val isBusyZip: Boolean = false,
    val statusMessage: String? = null,
    val errorMessage: String? = null
)

class LiveFodViewModel(application: Application) : AndroidViewModel(application) {

    private val storage = LiveFodStorageManager(application)

    private val _uiState = MutableStateFlow(
        LiveFodUiState(liveSessionsDirPath = storage.getLiveSessionsRootDir().absolutePath)
    )
    val uiState: StateFlow<LiveFodUiState> = _uiState.asStateFlow()

    private val _shareZipEvents = MutableSharedFlow<File>(extraBufferCapacity = 4)
    val shareZipEvents: SharedFlow<File> = _shareZipEvents.asSharedFlow()

    init {
        viewModelScope.launch {
            LiveFodController.hudState.collectLatest { hud ->
                _uiState.update { it.copy(hud = hud) }
            }
        }
        viewModelScope.launch {
            LiveFodController.completedSession.collectLatest { completed ->
                if (completed != null) {
                    refreshSessions(selectId = completed.metadata.id)
                }
            }
        }
        refreshSessions()
    }

    fun refreshSessions(selectId: String? = null) {
        viewModelScope.launch {
            val loaded = storage.listAllSessions()
            val rootPath = storage.getLiveSessionsRootDir().absolutePath
            _uiState.update { state ->
                val targetActive = when {
                    selectId != null -> loaded.find { it.metadata.id == selectId }
                    state.activeSession != null -> loaded.find { it.metadata.id == state.activeSession.metadata.id }
                    else -> null
                } ?: loaded.firstOrNull()

                val cmpA = state.selectedCompareAId?.takeIf { id -> loaded.any { it.metadata.id == id } }
                    ?: loaded.firstOrNull { !it.metadata.isDsuActive }?.metadata?.id
                    ?: loaded.firstOrNull()?.metadata?.id
                val cmpB = state.selectedCompareBId?.takeIf { id -> loaded.any { it.metadata.id == id } }
                    ?: loaded.firstOrNull { it.metadata.id != cmpA }?.metadata?.id

                state.copy(
                    sessions = loaded,
                    activeSession = targetActive,
                    selectedCompareAId = cmpA,
                    selectedCompareBId = cmpB,
                    liveSessionsDirPath = rootPath
                )
            }
        }
    }

    fun startLiveCapture(label: String) {
        _uiState.update { it.copy(errorMessage = null, statusMessage = null) }
        LiveFodController.startCapture(getApplication(), label)
    }

    fun markTouchMoment() {
        LiveFodController.markTouchMoment()
    }

    fun stopLiveCapture() {
        LiveFodController.requestStopAndCompile(getApplication())
    }

    fun openFingerprintEnrollSettings() {
        val ok = LiveFodController.openFingerprintEnrollSettings(getApplication())
        if (!ok) {
            _uiState.update { it.copy(errorMessage = "Impossible d'ouvrir automatiquement les Paramètres d'empreinte.") }
        }
    }

    fun selectSession(session: LiveFodSession) {
        _uiState.update { it.copy(activeSession = session) }
    }

    fun deleteSession(session: LiveFodSession) {
        viewModelScope.launch {
            storage.deleteSession(session)
            refreshSessions()
            _uiState.update { it.copy(statusMessage = "Session Live supprimée : ${session.metadata.displayName}") }
        }
    }

    fun readSubFilePreview(session: LiveFodSession, relativePath: String): String {
        return storage.readSessionSubFilePreview(session, relativePath)
    }

    fun importLiveZip(uri: Uri) {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusyZip = true, errorMessage = null) }
            val result = storage.importLiveZipFromUri(uri)
            result.fold(
                onSuccess = { imported ->
                    _uiState.update {
                        it.copy(
                            isBusyZip = false,
                            statusMessage = "Session Live FOD dézippée dans /sdcard/FOD Database/LiveFodSessions : ${imported.metadata.displayName}"
                        )
                    }
                    refreshSessions(selectId = imported.metadata.id)
                },
                onFailure = { err ->
                    _uiState.update {
                        it.copy(
                            isBusyZip = false,
                            errorMessage = "Échec import Live .ZIP : ${err.localizedMessage ?: "archive incompatible"}"
                        )
                    }
                }
            )
        }
    }

    fun exportActiveSessionZip(shareAfter: Boolean = false) {
        val session = _uiState.value.activeSession ?: return
        viewModelScope.launch {
            _uiState.update { it.copy(isBusyZip = true, errorMessage = null) }
            try {
                val zipFile = storage.exportSessionToZip(session)
                _uiState.update {
                    it.copy(
                        isBusyZip = false,
                        statusMessage = "Archive Live FOD exportée : ${zipFile.absolutePath}"
                    )
                }
                refreshSessions(selectId = session.metadata.id)
                if (shareAfter) _shareZipEvents.emit(zipFile)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusyZip = false,
                        errorMessage = "Échec export Live .ZIP : ${e.localizedMessage ?: "erreur"}"
                    )
                }
            }
        }
    }

    fun selectComparisonPair(idA: String?, idB: String?) {
        _uiState.update { it.copy(selectedCompareAId = idA, selectedCompareBId = idB) }
    }

    fun runLiveComparison() {
        val state = _uiState.value
        val sA = state.sessions.find { it.metadata.id == state.selectedCompareAId }
        val sB = state.sessions.find { it.metadata.id == state.selectedCompareBId }
        if (sA == null || sB == null) {
            _uiState.update { it.copy(errorMessage = "Sélectionnez deux sessions Live distinctes (A et B).") }
            return
        }
        viewModelScope.launch(Dispatchers.Default) {
            val report = LiveFodComparator.compare(sA, sB)
            _uiState.update {
                it.copy(
                    comparisonReport = report,
                    statusMessage = "Comparaison Live générée (${report.items.size} écarts, ${report.blockersCount} bloquants)."
                )
            }
        }
    }

    fun exportLiveComparisonZip(shareAfter: Boolean = false) {
        val state = _uiState.value
        val report = state.comparisonReport ?: return
        val sA = state.sessions.find { it.metadata.id == report.sessionA.id } ?: return
        val sB = state.sessions.find { it.metadata.id == report.sessionB.id } ?: return
        viewModelScope.launch {
            _uiState.update { it.copy(isBusyZip = true, errorMessage = null) }
            try {
                val zip = storage.exportLiveComparisonToZip(report, sA, sB)
                _uiState.update {
                    it.copy(
                        isBusyZip = false,
                        comparisonReport = report.copy(exportedZipPath = zip.absolutePath),
                        statusMessage = "Pack Comparaison Live FOD exporté : ${zip.absolutePath}"
                    )
                }
                if (shareAfter) _shareZipEvents.emit(zip)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusyZip = false,
                        errorMessage = "Échec export comparaison Live .ZIP : ${e.localizedMessage ?: "erreur"}"
                    )
                }
            }
        }
    }

    fun clearMessages() {
        _uiState.update { it.copy(statusMessage = null, errorMessage = null) }
    }
}

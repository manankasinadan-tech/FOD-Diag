package com.example.ui.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.core.FodComparatorEngine
import com.example.core.FodDatabaseManager
import com.example.core.FodInvestigationEngine
import com.example.core.LabSettings
import com.example.core.PermissionHelper
import com.example.core.RootShellExecutor
import com.example.core.SettingsPreferences
import com.example.model.AnalysisProgress
import com.example.model.ComparisonReport
import com.example.model.EnvironmentStatus
import com.example.model.FodSnapshot
import com.example.model.RomEnvironmentType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

data class FodLabUiState(
    val envStatus: EnvironmentStatus = EnvironmentStatus(
        rootGranted = false,
        rootProvider = "Vérification...",
        rootDetail = "Initialisation du contrôle superutilisateur",
        storageGranted = false,
        databasePath = "/sdcard/FOD Database",
        databaseWritable = false,
        isDsuDetected = false,
        detectedRomType = RomEnvironmentType.INDETERMINE,
        seLinuxMode = "?"
    ),
    val settings: LabSettings = LabSettings(),
    val progress: AnalysisProgress = AnalysisProgress(),
    val snapshots: List<FodSnapshot> = emptyList(),
    val activeSnapshot: FodSnapshot? = null,
    val selectedSnapshotAId: String? = null,
    val selectedSnapshotBId: String? = null,
    val comparisonReport: ComparisonReport? = null,
    val lastExportedZip: File? = null,
    val isBusyImportingOrExporting: Boolean = false,
    val statusBannerMessage: String? = null,
    val errorBannerMessage: String? = null
)

sealed interface LabUiEvent {
    data object NavigateToDashboard : LabUiEvent
    data class ShareZipFile(val file: File) : LabUiEvent
}

class FodLabViewModel(application: Application) : AndroidViewModel(application) {

    private val shell = RootShellExecutor()
    private val engine = FodInvestigationEngine(shell, application)
    private val dbManager = FodDatabaseManager(application, shell)
    private val prefs = SettingsPreferences(application)

    private val _uiState = MutableStateFlow(FodLabUiState())
    val uiState: StateFlow<FodLabUiState> = _uiState.asStateFlow()

    private val _events = MutableSharedFlow<LabUiEvent>(extraBufferCapacity = 8)
    val events: SharedFlow<LabUiEvent> = _events.asSharedFlow()

    init {
        viewModelScope.launch {
            prefs.settingsFlow.collect { s ->
                _uiState.update { it.copy(settings = s) }
            }
        }
        refreshEnvironmentAndSnapshots()
    }

    fun refreshEnvironmentAndSnapshots() {
        viewModelScope.launch {
            val ctx = getApplication<Application>()
            val storageOk = PermissionHelper.hasStoragePermission(ctx)
            val primaryWritable = withContext(Dispatchers.IO) { dbManager.isPrimarySdcardWritable() }
            val activeDir = withContext(Dispatchers.IO) { dbManager.getActiveDatabaseDir().absolutePath }

            val rootInfo = shell.detectRoot(forceRecheck = true)
            val seMode = shell.exec("getenforce 2>/dev/null || cat /sys/fs/selinux/enforce 2>/dev/null", preferRoot = true)
                .stdout.trim().ifBlank { "Inconnu" }
            val propsCheck = shell.exec("getprop ro.gsid.image_running; getprop ro.product.system.name; getprop ro.build.flavor; mount | grep dsu", preferRoot = true).stdout
            val isDsu = propsCheck.contains("1") || propsCheck.contains("gsi", ignoreCase = true) || propsCheck.contains("/dsu", ignoreCase = true)

            val loadedSnapshots = dbManager.listAllSnapshots()
            val currentActive = _uiState.value.activeSnapshot?.let { prev ->
                loadedSnapshots.find { it.metadata.id == prev.metadata.id }
            } ?: loadedSnapshots.firstOrNull()

            val snapA = _uiState.value.selectedSnapshotAId?.takeIf { id -> loadedSnapshots.any { it.metadata.id == id } }
                ?: loadedSnapshots.firstOrNull { !it.metadata.isDsuActive }?.metadata?.id
                ?: loadedSnapshots.firstOrNull()?.metadata?.id

            val snapB = _uiState.value.selectedSnapshotBId?.takeIf { id -> loadedSnapshots.any { it.metadata.id == id } }
                ?: loadedSnapshots.firstOrNull { it.metadata.id != snapA }?.metadata?.id

            _uiState.update {
                it.copy(
                    envStatus = EnvironmentStatus(
                        rootGranted = rootInfo.isGranted,
                        rootProvider = rootInfo.provider,
                        rootDetail = rootInfo.detail,
                        storageGranted = storageOk,
                        databasePath = activeDir,
                        databaseWritable = primaryWritable,
                        isDsuDetected = isDsu,
                        detectedRomType = if (isDsu) RomEnvironmentType.GSI_DSU else RomEnvironmentType.ROM_ORIGINE,
                        seLinuxMode = seMode
                    ),
                    snapshots = loadedSnapshots,
                    activeSnapshot = currentActive,
                    selectedSnapshotAId = snapA,
                    selectedSnapshotBId = snapB
                )
            }
        }
    }

    fun testRootPermissionExplicitly() {
        viewModelScope.launch {
            val rootInfo = shell.detectRoot(forceRecheck = true)
            _uiState.update { state ->
                state.copy(
                    envStatus = state.envStatus.copy(
                        rootGranted = rootInfo.isGranted,
                        rootProvider = rootInfo.provider,
                        rootDetail = rootInfo.detail
                    ),
                    statusBannerMessage = if (rootInfo.isGranted) {
                        "Autorisation Root confirmée (${rootInfo.provider})."
                    } else {
                        null
                    },
                    errorBannerMessage = if (!rootInfo.isGranted) {
                        "Root refusé ou indisponible : ${rootInfo.detail}"
                    } else {
                        null
                    }
                )
            }
        }
    }

    fun launchFodAnalysis() {
        if (_uiState.value.progress.isRunning) return
        viewModelScope.launch {
            _uiState.update { it.copy(errorBannerMessage = null, statusBannerMessage = null) }
            try {
                val activeDir = withContext(Dispatchers.IO) { dbManager.getActiveDatabaseDir().absolutePath }
                val snapshot = engine.runFullInvestigation(
                    databaseDirPath = activeDir,
                    deepBinaryInspection = _uiState.value.settings.deepBinaryInspection
                ) { prog ->
                    _uiState.update { it.copy(progress = prog) }
                }

                val saved = dbManager.saveSnapshot(snapshot)
                val allSnapshots = dbManager.listAllSnapshots()

                _uiState.update { state ->
                    state.copy(
                        snapshots = allSnapshots,
                        activeSnapshot = saved,
                        selectedSnapshotAId = state.selectedSnapshotAId ?: saved.metadata.id,
                        selectedSnapshotBId = if (state.selectedSnapshotAId != null && state.selectedSnapshotAId != saved.metadata.id) {
                            saved.metadata.id
                        } else {
                            state.selectedSnapshotBId
                        },
                        statusBannerMessage = "Analyse terminée et enregistrée dans ${saved.metadata.snapshotDirPath}"
                    )
                }

                if (_uiState.value.settings.autoOpenDashboardAfterScan) {
                    _events.emit(LabUiEvent.NavigateToDashboard)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        progress = AnalysisProgress(isRunning = false),
                        errorBannerMessage = "Échec lors de l'analyse FOD : ${e.localizedMessage ?: "erreur inconnue"}"
                    )
                }
            }
        }
    }

    fun selectActiveSnapshot(snapshot: FodSnapshot) {
        _uiState.update { it.copy(activeSnapshot = snapshot) }
    }

    fun exportActiveSnapshotToZip(shareAfterExport: Boolean = false) {
        val target = _uiState.value.activeSnapshot ?: return
        viewModelScope.launch {
            _uiState.update { it.copy(isBusyImportingOrExporting = true, errorBannerMessage = null) }
            try {
                val zipFile = dbManager.exportSnapshotToZip(target)
                val updatedSnapshots = dbManager.listAllSnapshots()
                val updatedActive = updatedSnapshots.find { it.metadata.id == target.metadata.id } ?: target
                _uiState.update {
                    it.copy(
                        isBusyImportingOrExporting = false,
                        lastExportedZip = zipFile,
                        snapshots = updatedSnapshots,
                        activeSnapshot = updatedActive,
                        statusBannerMessage = "Archive .zip créée : ${zipFile.absolutePath}"
                    )
                }
                if (shareAfterExport) {
                    _events.emit(LabUiEvent.ShareZipFile(zipFile))
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusyImportingOrExporting = false,
                        errorBannerMessage = "Impossible d'exporter en .zip : ${e.localizedMessage}"
                    )
                }
            }
        }
    }

    fun importZipArchive(uri: Uri) {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusyImportingOrExporting = true, errorBannerMessage = null) }
            val result = dbManager.importZipFromUri(uri)
            result.fold(
                onSuccess = { imported ->
                    val allSnapshots = dbManager.listAllSnapshots()
                    _uiState.update { state ->
                        val newA = state.selectedSnapshotAId ?: imported.metadata.id
                        val newB = if (newA != imported.metadata.id) imported.metadata.id else state.selectedSnapshotBId
                        state.copy(
                            isBusyImportingOrExporting = false,
                            snapshots = allSnapshots,
                            activeSnapshot = imported,
                            selectedSnapshotAId = newA,
                            selectedSnapshotBId = newB,
                            statusBannerMessage = "Archive dézippée dans /sdcard/FOD Database : ${imported.metadata.displayName}"
                        )
                    }
                },
                onFailure = { err ->
                    _uiState.update {
                        it.copy(
                            isBusyImportingOrExporting = false,
                            errorBannerMessage = "Échec d'importation ZIP : ${err.localizedMessage ?: "format invalide"}"
                        )
                    }
                }
            )
        }
    }

    fun selectComparisonSnapshots(idA: String?, idB: String?) {
        _uiState.update { it.copy(selectedSnapshotAId = idA, selectedSnapshotBId = idB) }
    }

    fun runComparison() {
        val state = _uiState.value
        val snapA = state.snapshots.find { it.metadata.id == state.selectedSnapshotAId }
        val snapB = state.snapshots.find { it.metadata.id == state.selectedSnapshotBId }
        if (snapA == null || snapB == null) {
            _uiState.update { it.copy(errorBannerMessage = "Sélectionnez deux captures distinctes (A et B) pour comparer.") }
            return
        }
        viewModelScope.launch(Dispatchers.Default) {
            val report = FodComparatorEngine.compare(snapA, snapB)
            _uiState.update {
                it.copy(
                    comparisonReport = report,
                    statusBannerMessage = "Comparaison factuelle générée (${report.diffs.size} écarts analysés)."
                )
            }
        }
    }

    fun deleteSnapshot(snapshot: FodSnapshot) {
        viewModelScope.launch {
            dbManager.deleteSnapshot(snapshot)
            val all = dbManager.listAllSnapshots()
            _uiState.update {
                it.copy(
                    snapshots = all,
                    activeSnapshot = if (it.activeSnapshot?.metadata?.id == snapshot.metadata.id) all.firstOrNull() else it.activeSnapshot,
                    statusBannerMessage = "Capture supprimée de la base de connaissances."
                )
            }
        }
    }

    fun setDeepBinaryInspection(enabled: Boolean) {
        viewModelScope.launch { prefs.setDeepBinaryInspection(enabled) }
    }

    fun setDarkTheme(enabled: Boolean) {
        viewModelScope.launch { prefs.setDarkTheme(enabled) }
    }

    fun setAutoOpenDashboard(enabled: Boolean) {
        viewModelScope.launch { prefs.setAutoOpenDashboard(enabled) }
    }

    fun clearBanners() {
        _uiState.update { it.copy(statusBannerMessage = null, errorBannerMessage = null) }
    }
}

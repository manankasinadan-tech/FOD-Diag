package com.example.livefod

import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import com.example.core.RootShellExecutor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

object LiveFodController {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _hudState = MutableStateFlow(LiveCaptureHudState())
    val hudState: StateFlow<LiveCaptureHudState> = _hudState.asStateFlow()

    private val _completedSession = MutableStateFlow<LiveFodSession?>(null)
    val completedSession: StateFlow<LiveFodSession?> = _completedSession.asStateFlow()

    private val stopSignal = AtomicBoolean(false)
    private val touchMarkerCount = AtomicInteger(0)

    @Volatile
    private var activeJob: Job? = null

    fun isRunning(): Boolean {
        val p = _hudState.value.phase
        return p == LiveCapturePhase.CAPTURING_PRE ||
            p == LiveCapturePhase.RECORDING_LIVE ||
            p == LiveCapturePhase.CAPTURING_POST_AND_EXTRACTING
    }

    fun startCapture(context: Context, sessionLabel: String) {
        if (isRunning()) return
        val appCtx = context.applicationContext
        val intent = Intent(appCtx, LiveFodCaptureService::class.java).apply {
            action = LiveFodCaptureService.ACTION_START
            putExtra(LiveFodCaptureService.EXTRA_SESSION_LABEL, sessionLabel)
        }
        ContextCompat.startForegroundService(appCtx, intent)
    }

    fun markTouchMoment() {
        if (_hudState.value.phase == LiveCapturePhase.RECORDING_LIVE) {
            touchMarkerCount.incrementAndGet()
        }
    }

    fun signalStopOnly() {
        stopSignal.set(true)
    }

    fun requestStopAndCompile(context: Context) {
        stopSignal.set(true)
    }

    fun openFingerprintEnrollSettings(context: Context): Boolean {
        val candidates = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                add(Intent(Settings.ACTION_BIOMETRIC_ENROLL))
            }
            @Suppress("DEPRECATION")
            add(Intent(Settings.ACTION_FINGERPRINT_ENROLL))
            add(Intent(Settings.ACTION_SECURITY_SETTINGS))
            add(Intent(Settings.ACTION_SETTINGS))
        }
        for (intent in candidates) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val launched = runCatching {
                context.startActivity(intent)
                true
            }.getOrDefault(false)
            if (launched) return true
        }
        return false
    }

    internal fun launchOrchestratorInsideService(
        appContext: Context,
        sessionLabel: String,
        onFinished: () -> Unit
    ) {
        if (activeJob?.isActive == true) return
        stopSignal.set(false)
        touchMarkerCount.set(0)
        val shell = RootShellExecutor()
        val storage = LiveFodStorageManager(appContext)
        val orchestrator = LiveFodOrchestrator(shell, storage)

        activeJob = scope.launch {
            try {
                val session = orchestrator.runSession(
                    sessionLabel = sessionLabel,
                    stopSignal = stopSignal,
                    touchMarkerCount = touchMarkerCount,
                    onHudUpdate = { transform -> _hudState.update(transform) }
                )
                _completedSession.value = session
            } catch (e: Exception) {
                _hudState.update {
                    it.copy(
                        phase = LiveCapturePhase.ERROR,
                        errorMessage = e.localizedMessage ?: "Erreur inconnue durant Live FOD"
                    )
                }
            } finally {
                onFinished()
            }
        }
    }
}

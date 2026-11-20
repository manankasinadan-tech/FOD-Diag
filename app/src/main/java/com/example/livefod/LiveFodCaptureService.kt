package com.example.livefod

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class LiveFodCaptureService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var hudObserverJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureNotificationChannel()

        when (intent?.action) {
            ACTION_MARK_TOUCH -> {
                LiveFodController.markTouchMoment()
                return START_STICKY
            }
            ACTION_STOP -> {
                LiveFodController.signalStopOnly()
                updateNotification(LiveFodController.hudState.value)
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val label = intent.getStringExtra(EXTRA_SESSION_LABEL).orEmpty()
                val initialNotif = buildNotification(LiveFodController.hudState.value)
                startForeground(NOTIFICATION_ID, initialNotif)

                hudObserverJob?.cancel()
                hudObserverJob = serviceScope.launch {
                    LiveFodController.hudState.collectLatest { state ->
                        updateNotification(state)
                    }
                }

                LiveFodController.launchOrchestratorInsideService(
                    appContext = applicationContext,
                    sessionLabel = label
                ) {
                    hudObserverJob?.cancel()
                    stopForeground(STOP_FOREGROUND_DETACH)
                    postCompletionSummaryNotification(LiveFodController.hudState.value)
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        hudObserverJob?.cancel()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val ch = NotificationChannel(
                CHANNEL_ID,
                "Capture Live FOD",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Affiche le compteur en direct et permet d'arrêter l'interception FOD depuis les Paramètres Android."
            }
            nm.createNotificationChannel(ch)
        }
    }

    private fun updateNotification(state: LiveCaptureHudState) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(state))
    }

    private fun buildNotification(state: LiveCaptureHudState): Notification {
        val openAppIntent = PendingIntent.getActivity(
            this,
            10,
            Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val markTouchIntent = PendingIntent.getService(
            this,
            11,
            Intent(this, LiveFodCaptureService::class.java).apply { action = ACTION_MARK_TOUCH },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this,
            12,
            Intent(this, LiveFodCaptureService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val title = when (state.phase) {
            LiveCapturePhase.CAPTURING_PRE -> "Live FOD — Capture initiale T0..."
            LiveCapturePhase.RECORDING_LIVE -> "Live FOD actif (${state.elapsedSeconds}s) • ${state.filteredFodEvents + state.touchEvents + state.sysfsTransitions} évts"
            LiveCapturePhase.CAPTURING_POST_AND_EXTRACTING -> "Live FOD — Compilation fichiers & codes sources..."
            else -> "Live FOD"
        }

        val body = if (state.phase == LiveCapturePhase.RECORDING_LIVE) {
            "Log:${state.filteredFodEvents} | Touch:${state.touchEvents} | Sysfs:${state.sysfsTransitions} | HAL:${state.halProcSnapshots}"
        } else {
            state.lastLiveHeadline.ifBlank { "Enregistrement en cours..." }
        }

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$body\n${state.lastLiveHeadline}"))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openAppIntent)

        if (state.phase == LiveCapturePhase.RECORDING_LIVE) {
            builder.addAction(0, "Marquer toucher", markTouchIntent)
            builder.addAction(0, "Arrêter & Compiler", stopIntent)
        }
        return builder.build()
    }

    private fun postCompletionSummaryNotification(state: LiveCaptureHudState) {
        val openAppIntent = PendingIntent.getActivity(
            this,
            13,
            Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val done = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_save)
            .setContentTitle("Live FOD terminé")
            .setContentText(state.lastLiveHeadline.ifBlank { "Session compilée dans /sdcard/FOD Database/" })
            .setAutoCancel(true)
            .setOngoing(false)
            .setContentIntent(openAppIntent)
            .build()
        nm.notify(NOTIFICATION_DONE_ID, done)
    }

    companion object {
        const val CHANNEL_ID = "live_fod_capture"
        const val NOTIFICATION_ID = 4201
        const val NOTIFICATION_DONE_ID = 4202
        const val ACTION_START = "com.example.livefod.ACTION_START"
        const val ACTION_MARK_TOUCH = "com.example.livefod.ACTION_MARK_TOUCH"
        const val ACTION_STOP = "com.example.livefod.ACTION_STOP"
        const val EXTRA_SESSION_LABEL = "extra_session_label"
    }
}

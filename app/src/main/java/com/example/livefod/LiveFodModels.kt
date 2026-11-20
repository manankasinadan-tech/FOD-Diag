package com.example.livefod

import androidx.compose.runtime.Immutable
import com.example.model.RomEnvironmentType

enum class LiveCapturePhase(val labelFr: String) {
    IDLE("Prêt pour une capture Live"),
    CAPTURING_PRE("Capture de l'état initial (Avant)"),
    RECORDING_LIVE("Interception Live active (allez dans Paramètres ➔ Empreintes)"),
    CAPTURING_POST_AND_EXTRACTING("Arrêt : extraction des fichiers, chaîne & codes sources..."),
    COMPLETED("Session Live FOD compilée"),
    ERROR("Erreur de capture Live FOD")
}

enum class LiveEventSource(val labelFr: String) {
    LOGCAT_FOD("Logcat / Système"),
    DMESG_KERNEL("Noyau (dmesg)"),
    TOUCH_GETEVENT("Tactile (getevent)"),
    SYSFS_POLL("Transition Sysfs"),
    HAL_PROC("Processus /proc & strace"),
    BINDER_IPC("Binder / lshal / IPC"),
    DUMPSYS_STATE("Snapshot dumpsys / SF"),
    USER_MARKER("Repère utilisateur"),
    SELINUX_AVC("SELinux AVC")
}

enum class LiveOutcome(val labelFr: String) {
    REACTION_DETECTEE("Réaction détectée"),
    TRANSITION_ETAT("Transition d'état"),
    SILENCE_RADIO("Aucune réaction / Silence"),
    ERREUR_EXPLICITE("Erreur explicite"),
    INFO_TECHNIQUE("Information brute")
}

@Immutable
data class LiveInteractionEvent(
    val id: String,
    val timestampMs: Long,
    val relativeTimeLabel: String,
    val source: LiveEventSource,
    val actor: String,
    val outcome: LiveOutcome,
    val summary: String,
    val rawDetail: String
)

@Immutable
data class LiveCallChainHop(
    val order: Int,
    val hopName: String,
    val layerTag: String,
    val actorsObserved: List<String>,
    val filesAndNodesInvolved: List<String>,
    val outcome: LiveOutcome,
    val factualEvidence: String
)

@Immutable
data class LiveDiscoveredMechanism(
    val primaryArchitecture: String,
    val enrollmentVerdict: String,
    val explanationFr: String,
    val displayIlluminationMethod: String,
    val touchInteractionMethod: String,
    val binderAndHalDaemons: List<String>,
    val activePackagesInChain: List<String>,
    val errorSignatures: List<String>,
    val hops: List<LiveCallChainHop>
)

@Immutable
data class LiveSysfsTransition(
    val path: String,
    val category: String,
    val beforeValue: String,
    val duringValues: List<String>,
    val afterValue: String,
    val hasChanged: Boolean,
    val permissions: String,
    val seLinuxContext: String
)

@Immutable
data class LiveHalProcessSnapshot(
    val pid: String,
    val processName: String,
    val uid: String,
    val seLinuxContext: String,
    val cmdline: String,
    val openFds: List<String>,
    val mappedFiles: List<String>,
    val unixSockets: List<String>,
    val straceHighlights: List<String>
)

@Immutable
data class LiveExtractedFileRecord(
    val id: String,
    val category: String,
    val originalPath: String,
    val extractedRelPath: String?,
    val sourceCodeRelPath: String?,
    val sha256: String,
    val sizeBytes: Long,
    val kind: String,
    val reasonInChain: String,
    val rawPreview: String,
    val reconstructedSourceCode: String
)

@Immutable
data class LiveGeneratedPatch(
    val id: String,
    val fileName: String,
    val title: String,
    val kind: String,
    val targetPathHint: String,
    val description: String,
    val codeContent: String
)

@Immutable
data class LiveSessionMetadata(
    val id: String,
    val displayName: String,
    val romType: RomEnvironmentType,
    val isImported: Boolean,
    val deviceModel: String,
    val androidVersion: String,
    val sdkInt: Int,
    val buildFingerprint: String,
    val vendorFingerprint: String,
    val isDsuActive: Boolean,
    val rootGranted: Boolean,
    val rootProvider: String,
    val startedAtIso: String,
    val durationSec: Long,
    val sessionDirPath: String,
    val zipExportPath: String? = null,
    val totalRawLogLines: Int,
    val totalTimelineEvents: Int,
    val extractedFilesCount: Int,
    val reconstructedSourcesCount: Int,
    val patchesCount: Int,
    val detectedVerdict: String
)

@Immutable
data class LiveFodSession(
    val metadata: LiveSessionMetadata,
    val mechanism: LiveDiscoveredMechanism,
    val timelineEvents: List<LiveInteractionEvent>,
    val sysfsTransitions: List<LiveSysfsTransition>,
    val halProcesses: List<LiveHalProcessSnapshot>,
    val extractedFiles: List<LiveExtractedFileRecord>,
    val patches: List<LiveGeneratedPatch>,
    val rawFilesManifest: Map<String, String>,
    val beforeAfterDeltaSummary: String,
    val reportMarkdown: String
)

@Immutable
data class LiveCaptureHudState(
    val phase: LiveCapturePhase = LiveCapturePhase.IDLE,
    val sessionId: String = "",
    val sessionLabel: String = "",
    val elapsedSeconds: Long = 0L,
    val touchMarkersCount: Int = 0,
    val logcatRawLines: Int = 0,
    val filteredFodEvents: Int = 0,
    val dmesgEvents: Int = 0,
    val touchEvents: Int = 0,
    val sysfsTransitions: Int = 0,
    val halProcSnapshots: Int = 0,
    val lastLiveHeadline: String = "",
    val recentLiveLogs: List<String> = emptyList(),
    val errorMessage: String? = null
)

@Immutable
data class LiveComparisonDiffItem(
    val id: String,
    val domain: String,
    val subject: String,
    val valueInA: String,
    val valueInB: String,
    val isCriticalBlocker: Boolean,
    val factualExplanation: String,
    val imitationAction: String
)

@Immutable
data class LiveComparisonReport(
    val sessionA: LiveSessionMetadata,
    val sessionB: LiveSessionMetadata,
    val causalSummaryFr: String,
    val blockersCount: Int,
    val items: List<LiveComparisonDiffItem>,
    val differentialPatches: List<LiveGeneratedPatch>,
    val reportMarkdown: String,
    val exportedZipPath: String? = null
)

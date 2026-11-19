package com.example.model

import androidx.compose.runtime.Immutable

enum class SystemLayer(val labelFr: String, val order: Int) {
    FRAMEWORK("Framework & SystemUI", 0),
    HAL("HAL Biométrique (AIDL/HIDL)", 1),
    VENDOR("Vendor & Bibliothèques ELF", 2),
    DISPLAY("Affichage, HBM & SurfaceFlinger", 3),
    TOUCH("Contrôleur Tactile & Événements", 4),
    KERNEL("Noyau, Sysfs & Pilotes", 5),
    DEVICE_TREE("Device Tree (FDT)", 6),
    SELINUX("SELinux & Permissions", 7)
}

enum class RomEnvironmentType(val labelFr: String) {
    ROM_ORIGINE("ROM d'origine"),
    GSI_DSU("GSI / DSU Sideloader"),
    INDETERMINE("Environnement personnalisé")
}

enum class SeverityLevel(val labelFr: String) {
    CRITIQUE("Critique"),
    AVERTISSEMENT("Avertissement"),
    INFO("Information"),
    CONFORME("Conforme")
}

enum class NodeStatus(val labelFr: String) {
    ACTIF("Actif"),
    MANQUANT("Manquant"),
    CASSE("Lien cassé"),
    PATCH_CONSTRUCTEUR("Patch constructeur"),
    PROTEGE("Protégé / Restreint")
}

@Immutable
data class ElfAnalysis(
    val machine: String,
    val is64Bit: Boolean,
    val soName: String?,
    val neededLibraries: List<String>,
    val resolvedDependencies: Map<String, String> = emptyMap(),
    val missingLibraries: List<String>,
    val fodSymbols: List<String>,
    val exportedSymbols: List<String> = emptyList(),
    val importedSymbols: List<String> = emptyList(),
    val fodStrings: List<String>,
    val pseudoSourceCode: String = ""
)

@Immutable
data class DexRroAnalysis(
    val sourcePath: String,
    val packageName: String?,
    val rroTargetPackage: String?,
    val rroPriority: Int?,
    val matchedClasses: List<String>,
    val matchedMethods: List<String>,
    val matchedConfigKeys: List<String>,
    val udfpsProperties: Map<String, String>,
    val decodedRroXml: String = "",
    val pseudoSourceCode: String = ""
)

@Immutable
data class DeviceTreeNode(
    val nodePath: String,
    val compatible: String?,
    val properties: Map<String, String>,
    val pseudoDtsi: String = ""
)

@Immutable
data class SelinuxFinding(
    val sourceType: String,
    val rawLine: String,
    val domain: String?,
    val targetType: String?,
    val tclass: String?,
    val permission: String?
)

@Immutable
data class DiscoveredArtifact(
    val id: String,
    val path: String,
    val layer: SystemLayer,
    val kind: String,
    val sha256: String,
    val sizeBytes: Long,
    val permissions: String,
    val seLinuxContext: String,
    val summary: String,
    val isOemPatch: Boolean = false,
    val elfAnalysis: ElfAnalysis? = null,
    val dexRroAnalysis: DexRroAnalysis? = null,
    val deviceTreeNode: DeviceTreeNode? = null,
    val rawExcerpt: String = "",
    val extractedRelativePath: String? = null,
    val pseudoSourcePath: String? = null
)

@Immutable
data class FodNode(
    val id: String,
    val label: String,
    val layer: SystemLayer,
    val status: NodeStatus,
    val details: String,
    val artifactPath: String? = null
)

@Immutable
data class FodEdge(
    val fromId: String,
    val toId: String,
    val relation: String,
    val isBroken: Boolean,
    val evidence: String
)

@Immutable
data class FodAnomaly(
    val id: String,
    val title: String,
    val severity: SeverityLevel,
    val layer: SystemLayer,
    val evidence: String,
    val impact: String,
    val portingAction: String
)

@Immutable
data class SnapshotMetadata(
    val id: String,
    val displayName: String,
    val romType: RomEnvironmentType,
    val isImported: Boolean,
    val deviceModel: String,
    val deviceManufacturer: String,
    val deviceCodename: String,
    val boardPlatform: String,
    val socModel: String,
    val androidVersion: String,
    val sdkInt: Int,
    val buildFingerprint: String,
    val vendorFingerprint: String,
    val kernelVersion: String,
    val seLinuxMode: String,
    val rootGranted: Boolean,
    val rootProvider: String,
    val isDsuActive: Boolean,
    val timestampIso: String,
    val snapshotDirPath: String,
    val zipExportPath: String? = null,
    val completenessScore: Int
)

@Immutable
data class FodSnapshot(
    val metadata: SnapshotMetadata,
    val artifacts: List<DiscoveredArtifact>,
    val nodes: List<FodNode>,
    val edges: List<FodEdge>,
    val anomalies: List<FodAnomaly>,
    val properties: Map<String, String>,
    val liveDumps: Map<String, String>,
    val selinuxFindings: List<SelinuxFinding>,
    val biometricExclusions: List<String>,
    val reportMarkdown: String,
    val phaseLogs: List<String>
)

@Immutable
data class EnvironmentStatus(
    val rootGranted: Boolean,
    val rootProvider: String,
    val rootDetail: String,
    val storageGranted: Boolean,
    val databasePath: String,
    val databaseWritable: Boolean,
    val isDsuDetected: Boolean,
    val detectedRomType: RomEnvironmentType,
    val seLinuxMode: String
)

enum class DiffCategory(val labelFr: String) {
    MANQUANT_DANS_B("Présent dans A, absent dans B"),
    NOUVEAU_DANS_B("Absent dans A, présent dans B"),
    MODIFIE_SHA256("Modifié (SHA-256 / contenu différent)"),
    PROPRIETE_DIVERGENTE("Propriété / Configuration divergente"),
    SELINUX_OU_DEPENDANCE("Dépendance ELF / Règle SELinux")
}

@Immutable
data class ComparisonDiffItem(
    val id: String,
    val category: DiffCategory,
    val layer: SystemLayer,
    val severity: SeverityLevel,
    val keyOrPath: String,
    val valueA: String,
    val valueB: String,
    val portingNote: String
)

@Immutable
data class ComparisonReport(
    val snapshotA: SnapshotMetadata,
    val snapshotB: SnapshotMetadata,
    val criticalBlockersCount: Int,
    val missingInBCount: Int,
    val modifiedShaCount: Int,
    val propertyDeltaCount: Int,
    val diffs: List<ComparisonDiffItem>,
    val portingChecklistFr: List<String>,
    val reportMarkdown: String
)

@Immutable
data class AnalysisProgress(
    val isRunning: Boolean = false,
    val currentPhaseIndex: Int = 0,
    val totalPhases: Int = 8,
    val currentPhaseTitle: String = "",
    val progressFraction: Float = 0f,
    val liveLogs: List<String> = emptyList()
)

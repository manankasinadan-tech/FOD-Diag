package com.example

import com.example.livefod.LiveCallChainHop
import com.example.livefod.LiveDiscoveredMechanism
import com.example.livefod.LiveExtractedFileRecord
import com.example.livefod.LiveFodComparator
import com.example.livefod.LiveFodSession
import com.example.livefod.LiveGeneratedPatch
import com.example.livefod.LiveHalProcessSnapshot
import com.example.livefod.LiveOutcome
import com.example.livefod.LiveSessionMetadata
import com.example.livefod.LiveSysfsTransition
import com.example.model.RomEnvironmentType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LiveFodUnitTest {

    @Test
    fun liveComparator_detectsBrokenExecutionHopsMissingMappedLibsAndFrozenSysfs() {
        val sessionStock = buildLiveSession(
            id = "LIVE_STOCK_1",
            romType = RomEnvironmentType.ROM_ORIGINE,
            hop3Outcome = LiveOutcome.REACTION_DETECTEE,
            hop3Evidence = "Layers SurfaceFlinger + sysfs lhbm_mode=1",
            mappedLibs = listOf("/vendor/lib64/hw/fingerprint.xiaomi.so", "/vendor/lib64/libdisplayfeature.so"),
            sysfsChanged = true,
            sysfsAfter = "1",
            errors = emptyList(),
            sePatch = "# Aucun refus"
        )
        val sessionGsi = buildLiveSession(
            id = "LIVE_GSI_1",
            romType = RomEnvironmentType.GSI_DSU,
            hop3Outcome = LiveOutcome.SILENCE_RADIO,
            hop3Evidence = "Aucune illumination HBM observée",
            mappedLibs = listOf("/vendor/lib64/hw/fingerprint.xiaomi.so"),
            sysfsChanged = false,
            sysfsAfter = "0",
            errors = listOf("SELinux AVC: avc: denied { write } for comm=hal scontext=u:r:hal_fingerprint_default:s0 tcontext=u:object_r:sysfs_disp:s0 tclass=file"),
            sePatch = "allow hal_fingerprint_default sysfs_disp:file { write };"
        )

        val report = LiveFodComparator.compare(sessionStock, sessionGsi)
        assertTrue(report.blockersCount >= 3)
        assertTrue(report.items.any { it.subject.contains("Étape 3") && it.isCriticalBlocker })
        assertTrue(report.items.any { it.subject.contains("libdisplayfeature.so") && it.isCriticalBlocker })
        assertTrue(report.items.any { it.subject.contains("lhbm_mode") && it.isCriticalBlocker })
        assertTrue(report.items.any { it.domain == "Erreur Live B" })

        val seDiff = report.differentialPatches.first { it.fileName == "diff_patch_selinux.te" }
        assertTrue(seDiff.codeContent.contains("allow hal_fingerprint_default sysfs_disp:file { write };"))
        val rcDiff = report.differentialPatches.first { it.fileName == "diff_patch_sysfs_init.rc" }
        assertTrue(rcDiff.codeContent.contains("/sys/class/drm/card0-DSI-1/lhbm_mode"))
        assertEquals(4, report.differentialPatches.size)
    }

    private fun buildLiveSession(
        id: String,
        romType: RomEnvironmentType,
        hop3Outcome: LiveOutcome,
        hop3Evidence: String,
        mappedLibs: List<String>,
        sysfsChanged: Boolean,
        sysfsAfter: String,
        errors: List<String>,
        sePatch: String
    ): LiveFodSession {
        return LiveFodSession(
            metadata = LiveSessionMetadata(
                id = id,
                displayName = id,
                romType = romType,
                isImported = false,
                deviceModel = "TestDevice",
                androidVersion = "14",
                sdkInt = 34,
                buildFingerprint = "fp/$id",
                vendorFingerprint = "vfp/$id",
                isDsuActive = romType == RomEnvironmentType.GSI_DSU,
                rootGranted = true,
                rootProvider = "Magisk",
                startedAtIso = "2026-11-19T20:00:00",
                durationSec = 12,
                sessionDirPath = "/sdcard/FOD Database/LiveFodSessions/$id",
                totalRawLogLines = 500,
                totalTimelineEvents = 25,
                extractedFilesCount = mappedLibs.size,
                reconstructedSourcesCount = mappedLibs.size,
                patchesCount = 1,
                detectedVerdict = if (errors.isEmpty()) "SUCCES" else "ECHEC"
            ),
            mechanism = LiveDiscoveredMechanism(
                primaryArchitecture = "fingerprint.xiaomi.so + displayfeature",
                enrollmentVerdict = if (errors.isEmpty()) "SUCCES" else "ECHEC",
                explanationFr = "Test",
                displayIlluminationMethod = hop3Evidence,
                touchInteractionMethod = "getevent",
                binderAndHalDaemons = listOf("displayfeature"),
                activePackagesInChain = listOf("SystemUI.apk"),
                errorSignatures = errors,
                hops = listOf(
                    LiveCallChainHop(
                        order = 3,
                        hopName = "Illumination Optique / Écran / Display HAL",
                        layerTag = "Affichage & HBM",
                        actorsObserved = listOf("displayfeature"),
                        filesAndNodesInvolved = listOf("/sys/class/drm/card0-DSI-1/lhbm_mode"),
                        outcome = hop3Outcome,
                        factualEvidence = hop3Evidence
                    )
                )
            ),
            timelineEvents = emptyList(),
            sysfsTransitions = listOf(
                LiveSysfsTransition(
                    path = "/sys/class/drm/card0-DSI-1/lhbm_mode",
                    category = "Affichage / HBM",
                    beforeValue = "0",
                    duringValues = if (sysfsChanged) listOf("0", "1") else listOf("0"),
                    afterValue = sysfsAfter,
                    hasChanged = sysfsChanged,
                    permissions = "-rw-rw-r--",
                    seLinuxContext = "u:object_r:sysfs_disp:s0"
                )
            ),
            halProcesses = listOf(
                LiveHalProcessSnapshot(
                    pid = "101",
                    processName = "/vendor/bin/hw/android.hardware.biometrics.fingerprint",
                    uid = "1000",
                    seLinuxContext = "u:r:hal_fingerprint_default:s0",
                    cmdline = "fingerprint",
                    openFds = listOf("0 -> /dev/goodix_fp"),
                    mappedFiles = mappedLibs,
                    unixSockets = emptyList(),
                    straceHighlights = emptyList()
                )
            ),
            extractedFiles = mappedLibs.mapIndexed { idx, p ->
                LiveExtractedFileRecord(
                    id = "f_$idx",
                    category = "Bibliothèques ELF (.so)",
                    originalPath = p,
                    extractedRelPath = "04_artefacts_extraits$p",
                    sourceCodeRelPath = "05_code_source_reconstruit$p.cpp",
                    sha256 = "sha_$idx",
                    sizeBytes = 1024L,
                    kind = "Bibliothèque native (.so)",
                    reasonInChain = "Chargé en mémoire",
                    rawPreview = p,
                    reconstructedSourceCode = "// source for $p"
                )
            },
            patches = listOf(
                LiveGeneratedPatch(
                    id = "se",
                    fileName = "patch_selinux_live.te",
                    title = "SELinux",
                    kind = "SELinux",
                    targetPathHint = "magiskpolicy",
                    description = "test",
                    codeContent = sePatch
                )
            ),
            rawFilesManifest = emptyMap(),
            beforeAfterDeltaSummary = "",
            reportMarkdown = "# Test"
        )
    }
}

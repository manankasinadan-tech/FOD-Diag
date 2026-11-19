package com.example

import com.example.core.BiometricPrivacyGuard
import com.example.core.ElfAnalyzer
import com.example.core.FodComparatorEngine
import com.example.model.DiscoveredArtifact
import com.example.model.ElfAnalysis
import com.example.model.FodSnapshot
import com.example.model.RomEnvironmentType
import com.example.model.SnapshotMetadata
import com.example.model.SystemLayer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FodEngineUnitTest {

    @Test
    fun biometricPrivacyGuard_blocksProtectedPaths() {
        assertTrue(BiometricPrivacyGuard.isProtectedBiometricPath("/data/vendor_de/0/fpdata/user.db"))
        assertTrue(BiometricPrivacyGuard.isProtectedBiometricPath("/data/system/users/0/fpdata"))
        assertTrue(BiometricPrivacyGuard.isProtectedBiometricPath("/mnt/vendor/persist/goodix/calib.bin"))
        assertTrue(BiometricPrivacyGuard.isProtectedBiometricPath("/data/vendor/tee/keybox"))
        assertFalse(BiometricPrivacyGuard.isProtectedBiometricPath("/vendor/lib64/hw/fingerprint.default.so"))
        assertFalse(BiometricPrivacyGuard.isProtectedBiometricPath("/sys/class/drm/card0-DSI-1/hbm"))
    }

    @Test
    fun elfAnalyzer_rejectsNonElfInputSafely() {
        val result = ElfAnalyzer.analyze("not an elf binary".toByteArray())
        assertNull(result)
    }

    @Test
    fun comparatorEngine_detectsMissingArtifactsAndElfDeps() {
        val snapStock = createTestSnapshot(
            id = "STOCK_1",
            romType = RomEnvironmentType.ROM_ORIGINE,
            artifacts = listOf(
                DiscoveredArtifact(
                    id = "a1",
                    path = "/vendor/lib64/hw/fingerprint.goodix.so",
                    layer = SystemLayer.HAL,
                    kind = "Bibliothèque ELF (.so)",
                    sha256 = "aaaa1111",
                    sizeBytes = 1024,
                    permissions = "-rw-r--r--",
                    seLinuxContext = "u:object_r:vendor_file:s0",
                    summary = "HAL Goodix",
                    elfAnalysis = ElfAnalysis(
                        machine = "AArch64 (arm64-v8a)",
                        is64Bit = true,
                        soName = "fingerprint.goodix.so",
                        neededLibraries = listOf("libgf_hal.so"),
                        missingLibraries = emptyList(),
                        fodSymbols = listOf("gf_fod_notify"),
                        fodStrings = emptyList()
                    )
                ),
                DiscoveredArtifact(
                    id = "a2",
                    path = "/vendor/overlay/UdfpsOverlay.apk",
                    layer = SystemLayer.FRAMEWORK,
                    kind = "Overlay RRO (lecture seule)",
                    sha256 = "bbbb2222",
                    sizeBytes = 2048,
                    permissions = "-rw-r--r--",
                    seLinuxContext = "u:object_r:vendor_overlay_file:s0",
                    summary = "RRO SystemUI",
                    isOemPatch = true
                )
            ),
            props = mapOf("persist.vendor.sys.fp.fod.location.X_Y" to "445,1920")
        )

        val snapGsi = createTestSnapshot(
            id = "GSI_1",
            romType = RomEnvironmentType.GSI_DSU,
            artifacts = listOf(
                DiscoveredArtifact(
                    id = "b1",
                    path = "/vendor/lib64/hw/fingerprint.goodix.so",
                    layer = SystemLayer.HAL,
                    kind = "Bibliothèque ELF (.so)",
                    sha256 = "cccc3333",
                    sizeBytes = 1024,
                    permissions = "-rw-r--r--",
                    seLinuxContext = "u:object_r:vendor_file:s0",
                    summary = "HAL Goodix",
                    elfAnalysis = ElfAnalysis(
                        machine = "AArch64 (arm64-v8a)",
                        is64Bit = true,
                        soName = "fingerprint.goodix.so",
                        neededLibraries = listOf("libgf_hal.so"),
                        missingLibraries = listOf("libgf_hal.so"),
                        fodSymbols = listOf("gf_fod_notify"),
                        fodStrings = emptyList()
                    )
                )
            ),
            props = emptyMap()
        )

        val report = FodComparatorEngine.compare(snapStock, snapGsi)
        assertEquals(1, report.missingInBCount)
        assertEquals(1, report.modifiedShaCount)
        assertEquals(1, report.propertyDeltaCount)
        assertTrue(report.criticalBlockersCount >= 2)
        assertTrue(report.portingChecklistFr.any { it.contains("UdfpsOverlay.apk") })
        assertTrue(report.portingChecklistFr.any { it.contains("libgf_hal.so") })
    }

    private fun createTestSnapshot(
        id: String,
        romType: RomEnvironmentType,
        artifacts: List<DiscoveredArtifact>,
        props: Map<String, String>
    ): FodSnapshot {
        return FodSnapshot(
            metadata = SnapshotMetadata(
                id = id,
                displayName = id,
                romType = romType,
                isImported = false,
                deviceModel = "TestDevice",
                deviceManufacturer = "TestOEM",
                deviceCodename = "testdev",
                boardPlatform = "taro",
                socModel = "sm8450",
                androidVersion = "14",
                sdkInt = 34,
                buildFingerprint = "fp/$id",
                vendorFingerprint = "vfp/$id",
                kernelVersion = "5.10",
                seLinuxMode = "Enforcing",
                rootGranted = true,
                rootProvider = "Magisk",
                isDsuActive = romType == RomEnvironmentType.GSI_DSU,
                timestampIso = "2026-11-18T12:00:00",
                snapshotDirPath = "/sdcard/FOD Database/$id",
                completenessScore = 80
            ),
            artifacts = artifacts,
            nodes = emptyList(),
            edges = emptyList(),
            anomalies = emptyList(),
            properties = props,
            liveDumps = emptyMap(),
            selinuxFindings = emptyList(),
            biometricExclusions = emptyList(),
            reportMarkdown = "# Rapport",
            phaseLogs = emptyList()
        )
    }
}

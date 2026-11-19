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
    fun elfAnalyzer_demanglesItaniumCppSymbols() {
        assertEquals(
            "vendor::goodix::FingerprintHal::onFingerDown",
            ElfAnalyzer.demangleItaniumSymbol("_ZN6vendor6goodix14FingerprintHal12onFingerDownEii")
        )
        assertEquals("gf_fod_notify", ElfAnalyzer.demangleItaniumSymbol("gf_fod_notify"))
    }

    @Test
    fun elfAnalyzer_parsesElf64DepsSymbolsAndPseudoSource() {
        val dynstrBytes = ("\u0000libgf_hal.so\u0000libmissing_oem.so\u0000fingerprint.goodix.so\u0000" +
            "_ZN6vendor6goodix14FingerprintHal12onFingerDownEv\u0000ioctl\u0000").toByteArray(Charsets.UTF_8)
        val dynstrText = String(dynstrBytes, Charsets.UTF_8)
        val offLibGf = 1
        val offMissing = dynstrText.indexOf("libmissing_oem.so")
        val offSoName = dynstrText.indexOf("fingerprint.goodix.so")
        val offExportSym = dynstrText.indexOf("_ZN6vendor6goodix14FingerprintHal12onFingerDownEv")
        val offImportSym = dynstrText.indexOf("ioctl")

        // Build minimal ELF64 LE:
        // 0..64: ELF64 header
        // 64..128: .dynamic (4 entries * 16 bytes: DT_NEEDED x2, DT_SONAME, DT_NULL)
        // 128..200: .dynsym (3 entries * 24 bytes: NULL, export, import)
        // 200..200+dynstrBytes.size: .dynstr
        // shoff = 200 + dynstrBytes.size (4 sections * 64 bytes)
        val dynOff = 64
        val dynSize = 64
        val symOff = 128
        val symSize = 72
        val strOff = 200
        val strSize = dynstrBytes.size
        val shOff = strOff + strSize
        val totalSize = shOff + 4 * 64

        val buf = java.nio.ByteBuffer.allocate(totalSize).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        // ELF magic + 64-bit LE
        buf.put(0, 0x7F.toByte())
        buf.put(1, 'E'.code.toByte())
        buf.put(2, 'L'.code.toByte())
        buf.put(3, 'F'.code.toByte())
        buf.put(4, 2.toByte()) // ELFCLASS64
        buf.put(5, 1.toByte()) // ELFDATA2LSB
        buf.putShort(18, 0xB7.toShort()) // EM_AARCH64
        buf.putLong(40, shOff.toLong())
        buf.putShort(58, 64.toShort())
        buf.putShort(60, 4.toShort())

        // .dynamic entries
        buf.putLong(dynOff, 1L) // DT_NEEDED
        buf.putLong(dynOff + 8, offLibGf.toLong())
        buf.putLong(dynOff + 16, 1L) // DT_NEEDED
        buf.putLong(dynOff + 24, offMissing.toLong())
        buf.putLong(dynOff + 32, 14L) // DT_SONAME
        buf.putLong(dynOff + 40, offSoName.toLong())
        buf.putLong(dynOff + 48, 0L) // DT_NULL

        // .dynsym entry 1: exported FOD C++ symbol (st_shndx = 1, STT_FUNC = 2)
        buf.putInt(symOff + 24, offExportSym)
        buf.put(symOff + 24 + 4, 0x12.toByte()) // STB_GLOBAL | STT_FUNC
        buf.putShort(symOff + 24 + 6, 1.toShort())

        // .dynsym entry 2: imported ioctl (st_shndx = 0, STT_FUNC = 2)
        buf.putInt(symOff + 48, offImportSym)
        buf.put(symOff + 48 + 4, 0x12.toByte())
        buf.putShort(symOff + 48 + 6, 0.toShort())

        // .dynstr bytes
        System.arraycopy(dynstrBytes, 0, buf.array(), strOff, strSize)

        // Section headers: [0]=NULL, [1]=.dynstr (type=3), [2]=.dynamic (type=6, link=1), [3]=.dynsym (type=11, link=1)
        val sh1 = shOff + 64
        buf.putInt(sh1 + 4, 3)
        buf.putLong(sh1 + 24, strOff.toLong())
        buf.putLong(sh1 + 32, strSize.toLong())

        val sh2 = shOff + 128
        buf.putInt(sh2 + 4, 6)
        buf.putLong(sh2 + 24, dynOff.toLong())
        buf.putLong(sh2 + 32, dynSize.toLong())
        buf.putInt(sh2 + 40, 1)

        val sh3 = shOff + 192
        buf.putInt(sh3 + 4, 11)
        buf.putLong(sh3 + 24, symOff.toLong())
        buf.putLong(sh3 + 32, symSize.toLong())
        buf.putInt(sh3 + 40, 1)
        buf.putLong(sh3 + 56, 24L)

        val parsed = ElfAnalyzer.analyze(
            bytes = buf.array(),
            availableLibraries = mapOf("libgf_hal.so" to "/vendor/lib64/libgf_hal.so"),
            sourcePath = "/vendor/lib64/hw/fingerprint.goodix.so"
        )!!

        assertEquals("AArch64 (arm64-v8a)", parsed.machine)
        assertEquals("fingerprint.goodix.so", parsed.soName)
        assertEquals(listOf("libgf_hal.so", "libmissing_oem.so"), parsed.neededLibraries)
        assertEquals("/vendor/lib64/libgf_hal.so", parsed.resolvedDependencies["libgf_hal.so"])
        assertEquals(listOf("libmissing_oem.so"), parsed.missingLibraries)
        assertTrue(parsed.exportedSymbols.any { it.contains("FingerprintHal::onFingerDown") })
        assertTrue(parsed.importedSymbols.contains("ioctl"))
        assertTrue(parsed.pseudoSourceCode.contains("RECONSTRUCTION QUASI-CODE SOURCE"))
        assertTrue(parsed.pseudoSourceCode.contains("/vendor/lib64/libgf_hal.so"))
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

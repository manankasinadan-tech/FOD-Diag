package com.example

import com.example.core.BiometricPrivacyGuard
import com.example.core.ElfAnalyzer
import com.example.core.FodComparatorEngine
import com.example.model.DexRroAnalysis
import com.example.model.DiffCategory
import com.example.model.DiscoveredArtifact
import com.example.model.ElfAnalysis
import com.example.model.FodSnapshot
import com.example.model.ProtectedAreaMetadata
import com.example.model.RomEnvironmentType
import com.example.model.SelinuxFinding
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

        val dynOff = 64
        val dynSize = 64
        val symOff = 128
        val symSize = 72
        val strOff = 200
        val strSize = dynstrBytes.size
        val shOff = strOff + strSize
        val totalSize = shOff + 4 * 64

        val buf = java.nio.ByteBuffer.allocate(totalSize).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buf.put(0, 0x7F.toByte())
        buf.put(1, 'E'.code.toByte())
        buf.put(2, 'L'.code.toByte())
        buf.put(3, 'F'.code.toByte())
        buf.put(4, 2.toByte())
        buf.put(5, 1.toByte())
        buf.putShort(18, 0xB7.toShort())
        buf.putLong(40, shOff.toLong())
        buf.putShort(58, 64.toShort())
        buf.putShort(60, 4.toShort())

        buf.putLong(dynOff, 1L)
        buf.putLong(dynOff + 8, offLibGf.toLong())
        buf.putLong(dynOff + 16, 1L)
        buf.putLong(dynOff + 24, offMissing.toLong())
        buf.putLong(dynOff + 32, 14L)
        buf.putLong(dynOff + 40, offSoName.toLong())
        buf.putLong(dynOff + 48, 0L)

        buf.putInt(symOff + 24, offExportSym)
        buf.put(symOff + 24 + 4, 0x12.toByte())
        buf.putShort(symOff + 24 + 6, 1.toShort())

        buf.putInt(symOff + 48, offImportSym)
        buf.put(symOff + 48 + 4, 0x12.toByte())
        buf.putShort(symOff + 48 + 6, 0.toShort())

        System.arraycopy(dynstrBytes, 0, buf.array(), strOff, strSize)

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

    @Test
    fun comparatorEngine_generatesGsiVerdictsPatchesPlanAndProtectedAreaAudit() {
        val snapStock = createTestSnapshot(
            id = "STOCK_DEEP",
            romType = RomEnvironmentType.ROM_ORIGINE,
            artifacts = listOf(
                DiscoveredArtifact(
                    id = "s_rro",
                    path = "/vendor/overlay/UdfpsOverlay.apk",
                    layer = SystemLayer.FRAMEWORK,
                    kind = "Overlay RRO",
                    sha256 = "rro_stock",
                    sizeBytes = 4096,
                    permissions = "-rw-r--r--",
                    seLinuxContext = "u:object_r:vendor_overlay_file:s0",
                    summary = "RRO UDFPS Stock",
                    isOemPatch = true,
                    dexRroAnalysis = DexRroAnalysis(
                        sourcePath = "/vendor/overlay/UdfpsOverlay.apk",
                        packageName = "com.oem.udfps.overlay",
                        rroTargetPackage = "com.android.systemui",
                        rroPriority = 900,
                        matchedClasses = listOf("com.android.systemui.biometrics.UdfpsController"),
                        matchedMethods = listOf("onFingerDown"),
                        matchedConfigKeys = listOf("config_udfps_sensor_props", "config_dozeAfterScreenOff"),
                        udfpsProperties = mapOf("config_udfps_sensor_props" to "540,2100,95")
                    )
                ),
                DiscoveredArtifact(
                    id = "s_hbm",
                    path = "/sys/class/drm/card0-DSI-1/hbm",
                    layer = SystemLayer.DISPLAY,
                    kind = "Noeud sysfs HBM",
                    sha256 = "hbm1",
                    sizeBytes = 8,
                    permissions = "-rw-rw-r--",
                    seLinuxContext = "u:object_r:sysfs_graphics:s0",
                    summary = "Sysfs HBM",
                    rawExcerpt = "0"
                )
            ),
            props = mapOf(
                "persist.vendor.sys.fp.fod.location.X_Y" to "540,2100",
                "ro.hardware.fingerprint" to "goodix"
            ),
            liveDumps = mapOf(
                "hal_services_lshal_dumpsys" to "vendor.goodix.hardware.biometrics.fingerprint@2.1::IGoodixFingerprintDaemon/default\nandroid.hardware.biometrics.fingerprint@2.3::IBiometricsFingerprint/default",
                "keystore_gatekeeper_tee_services" to "android.system.keystore2.IKeystoreService/default\nandroid.hardware.security.keymint.IKeyMintDevice/default\nandroid.hardware.gatekeeper.IGatekeeper/default"
            ),
            protectedAreaAudits = listOf(
                ProtectedAreaMetadata(
                    path = "/data/vendor_de/0/fpdata",
                    category = "Gabarits biométriques",
                    exists = true,
                    permissions = "drwx------",
                    ownerGroup = "1000:1000",
                    seLinuxContext = "u:object_r:fingerprint_vendor_data_file:s0",
                    entryCount = 2,
                    note = "Métadonnées uniquement"
                ),
                ProtectedAreaMetadata(
                    path = "/data/misc/keystore",
                    category = "Keystore",
                    exists = true,
                    permissions = "drwx------",
                    ownerGroup = "1017:1017",
                    seLinuxContext = "u:object_r:keystore_data_file:s0",
                    entryCount = 3,
                    note = "Métadonnées uniquement"
                )
            )
        )

        val snapGsi = createTestSnapshot(
            id = "GSI_DEEP",
            romType = RomEnvironmentType.GSI_DSU,
            artifacts = emptyList(),
            props = mapOf("ro.gsid.image_running" to "1"),
            liveDumps = mapOf(
                "hal_services_lshal_dumpsys" to "android.hardware.biometrics.fingerprint@2.1::IBiometricsFingerprint/default",
                "keystore_gatekeeper_tee_services" to "android.system.keystore2.IKeystoreService/default"
            ),
            selinuxFindings = listOf(
                SelinuxFinding(
                    sourceType = "AVC_DENIED",
                    rawLine = "avc: denied { read write } for comm=\"fingerprint\" scontext=u:r:hal_fingerprint_default:s0 tcontext=u:object_r:sysfs_graphics:s0 tclass=file",
                    domain = "hal_fingerprint_default",
                    targetType = "sysfs_graphics",
                    tclass = "file",
                    permission = "read"
                )
            ),
            protectedAreaAudits = listOf(
                ProtectedAreaMetadata(
                    path = "/data/vendor_de/0/fpdata",
                    category = "Gabarits biométriques",
                    exists = false,
                    permissions = "-",
                    ownerGroup = "-",
                    seLinuxContext = "-",
                    entryCount = 0,
                    note = "Absent dans GSI"
                ),
                ProtectedAreaMetadata(
                    path = "/data/misc/keystore",
                    category = "Keystore",
                    exists = true,
                    permissions = "drwx------",
                    ownerGroup = "1017:1017",
                    seLinuxContext = "u:object_r:unlabeled:s0",
                    entryCount = 0,
                    note = "Contexte SELinux dégradé"
                )
            )
        )

        val report = FodComparatorEngine.compare(snapStock, snapGsi)
        assertTrue(report.gsiFailureSummary.contains("Pourquoi le FOD échoue") || report.gsiFailureSummary.isNotBlank())
        assertEquals(SystemLayer.entries.size, report.layerVerdicts.size)
        assertTrue(report.layerVerdicts.any { it.isBlocking && it.imitationSolution.isNotBlank() })
        assertTrue(report.diffs.any { it.category == DiffCategory.BIO_KEYSTORE_TEE })
        assertTrue(report.diffs.any { it.category == DiffCategory.HAL_SERVICE_OU_SYSTEME })

        val patchFiles = report.generatedPatches.map { it.fileName }
        assertTrue(patchFiles.contains("fod_sepolicy_gsi.te"))
        assertTrue(patchFiles.contains("fod_system_props.prop"))
        assertTrue(patchFiles.contains("fod_rro_overlay_config.xml"))
        assertTrue(patchFiles.contains("fod_init_overlay.rc"))
        assertTrue(report.implementationPlanMarkdown.contains("PLAN D'IMPLÉMENTATION"))

        val sepolicyPatch = report.generatedPatches.first { it.fileName == "fod_sepolicy_gsi.te" }.codeContent
        assertTrue(sepolicyPatch.contains("allow hal_fingerprint_default sysfs_graphics:file { read };"))
        val initPatch = report.generatedPatches.first { it.fileName == "fod_init_overlay.rc" }.codeContent
        assertTrue(initPatch.contains("/data/vendor_de/0/fpdata"))
        assertTrue(initPatch.contains("restorecon_recursive /data/misc/keystore"))
    }

    private fun createTestSnapshot(
        id: String,
        romType: RomEnvironmentType,
        artifacts: List<DiscoveredArtifact>,
        props: Map<String, String>,
        liveDumps: Map<String, String> = emptyMap(),
        selinuxFindings: List<SelinuxFinding> = emptyList(),
        protectedAreaAudits: List<ProtectedAreaMetadata> = emptyList()
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
            liveDumps = liveDumps,
            selinuxFindings = selinuxFindings,
            biometricExclusions = emptyList(),
            reportMarkdown = "# Rapport",
            phaseLogs = emptyList(),
            protectedAreaAudits = protectedAreaAudits
        )
    }
}

package com.example.core

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.hardware.input.InputManager
import android.os.Build
import com.example.model.AnalysisProgress
import com.example.model.DiscoveredArtifact
import com.example.model.FodAnomaly
import com.example.model.FodEdge
import com.example.model.FodNode
import com.example.model.FodSnapshot
import com.example.model.NodeStatus
import com.example.model.ProtectedAreaMetadata
import com.example.model.RomEnvironmentType
import com.example.model.SelinuxFinding
import com.example.model.SeverityLevel
import com.example.model.SnapshotMetadata
import com.example.model.SystemLayer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

class FodInvestigationEngine(
    private val shell: RootShellExecutor = RootShellExecutor(),
    private val context: Context? = null
) {
    private val dtAndSysfs = DeviceTreeAndSysfsProbe(shell)

    suspend fun runFullInvestigation(
        databaseDirPath: String,
        deepBinaryInspection: Boolean = true,
        onProgress: (AnalysisProgress) -> Unit
    ): FodSnapshot = withContext(Dispatchers.Default) {
        val logs = mutableListOf<String>()
        val exclusions = mutableListOf<String>()
        val artifacts = mutableListOf<DiscoveredArtifact>()
        val anomalies = mutableListOf<FodAnomaly>()
        val selinuxFindings = mutableListOf<SelinuxFinding>()
        val liveDumps = LinkedHashMap<String, String>()
        val dynamicKeywords = LinkedHashSet<String>()

        fun emit(phaseIdx: Int, title: String, logMsg: String) {
            val timestamp = SimpleDateFormat("HH:mm:ss", Locale.FRANCE).format(Date())
            logs.add("[$timestamp] [$phaseIdx/8] $logMsg")
            onProgress(
                AnalysisProgress(
                    isRunning = true,
                    currentPhaseIndex = phaseIdx,
                    totalPhases = 8,
                    currentPhaseTitle = title,
                    progressFraction = phaseIdx / 8f,
                    liveLogs = logs.toList()
                )
            )
        }

        // ── PHASE 1 : ENVIRONNEMENT, ROOT, DSU/GSI & PROPRIÉTÉS ──────────────────────
        emit(1, "Environnement & Propriétés système", "Vérification de l'accès Root (Magisk/SU) et de la partition active...")
        val rootInfo = shell.detectRoot(forceRecheck = true)
        val seLinuxMode = shell.exec("getenforce 2>/dev/null || cat /sys/fs/selinux/enforce 2>/dev/null", preferRoot = true)
            .stdout.trim().ifBlank { "Inconnu" }
        val kernelVersion = shell.exec("uname -a 2>/dev/null || cat /proc/version 2>/dev/null", preferRoot = true)
            .stdout.trim().ifBlank { System.getProperty("os.version") ?: "Inconnu" }

        val getpropOut = shell.exec("getprop", preferRoot = true, timeoutMs = 10_000L).stdout
        val allProps = parseGetprop(getpropOut)
        liveDumps["getprop_complet"] = getpropOut
        liveDumps["mounts"] = shell.exec("cat /proc/mounts 2>/dev/null", preferRoot = true).stdout

        val isDsuActive = allProps.any { (k, v) ->
            (k.contains("gsid") || k.contains("dsu") || k.contains("treble")) &&
                (v.equals("1", true) || v.equals("true", true) || v.contains("gsi", true))
        } || (liveDumps["mounts"]?.contains("/dsu") == true) ||
            (allProps["ro.product.system.name"]?.contains("gsi", true) == true) ||
            (allProps["ro.build.flavor"]?.contains("gsi", true) == true)

        val romType = if (isDsuActive) RomEnvironmentType.GSI_DSU else RomEnvironmentType.ROM_ORIGINE

        val relevantProps = allProps.filter { (k, v) ->
            val kl = k.lowercase()
            val vl = v.lowercase()
            kl.contains("finger") || kl.contains("fod") || kl.contains("udfps") ||
                kl.contains("biometric") || kl.contains("hbm") || kl.contains("lhbm") ||
                kl.contains("display") || kl.contains("touch") || kl.contains("panel") ||
                kl.contains("vndk") || kl.contains("gsid") || kl.contains("treble") ||
                kl.contains("vendor.lineage") || kl.contains("persist.vendor") ||
                vl.contains("goodix") || vl.contains("fpc") || vl.contains("silead") ||
                vl.contains("focal") || vl.contains("udfps") || vl.contains("optical") ||
                vl.contains("ultrasonic")
        }

        // Extraction dynamique des mots-clés constructeur depuis les propriétés
        relevantProps.forEach { (k, v) ->
            extractDynamicTokens(k, dynamicKeywords)
            extractDynamicTokens(v, dynamicKeywords)
        }
        emit(1, "Environnement & Propriétés système", "Root: ${rootInfo.provider} | SELinux: $seLinuxMode | ${relevantProps.size} propriétés ciblées.")

        // ── PHASE 2 : SERVICES EN DIRECT (SDK + DUMPSYS/LSHAL/AIDL SOUS ROOT) ────────
        emit(2, "Inspection en direct HAL & Services", "Collecte des API live et des services HAL/Binder...")
        collectAndroidSdkLiveTelemetry(context, liveDumps, dynamicKeywords)

        if (rootInfo.isGranted) {
            val availableServicesOut = shell.exec("service list 2>/dev/null", preferRoot = true, timeoutMs = 8_000L).stdout
            val filteredServiceList = availableServicesOut.lines()
                .filter { line ->
                    val l = line.lowercase()
                    l.contains("finger") || l.contains("biometric") || l.contains("fod") ||
                        l.contains("udfps") || l.contains("display") || l.contains("surfaceflinger") ||
                        l.contains("touch") || l.contains("power") || l.contains("vibrator")
                }
                .take(150)
                .joinToString("\n")
            if (filteredServiceList.isNotBlank()) {
                liveDumps["service_list"] = filteredServiceList
                extractDynamicTokens(filteredServiceList, dynamicKeywords)
            }

            // --neat -i -t évite le parsing refPids qui provoque E/lshal: We failed to parse the pointer
            val lshalOut = shell.exec(
                "lshal --neat -i -t 2>/dev/null | grep -iE 'finger|biometric|fod|udfps|display|composer|touch|xiaomi|oplus|samsung|goodix|fpc|silead' | head -n 200",
                preferRoot = true,
                timeoutMs = 10_000L
            ).stdout.trim()
            if (lshalOut.isNotBlank()) {
                liveDumps["lshal_services"] = lshalOut
                extractDynamicTokens(lshalOut, dynamicKeywords)
            }

            val dumpsysList = shell.exec("dumpsys -l 2>/dev/null", preferRoot = true, timeoutMs = 6_000L)
                .stdout.lines().map { it.trim() }.toSet()

            val dumpSpecs = listOf(
                Triple("dumpsys_fingerprint", "fingerprint", "dumpsys fingerprint 2>/dev/null | head -n 600"),
                Triple("dumpsys_biometric", "biometric", "dumpsys biometric 2>/dev/null | head -n 450"),
                Triple("dumpsys_display", "display", "dumpsys display 2>/dev/null | grep -iE 'hbm|lhbm|brightness|udfps|fod|mode|oled|hdr|color|refresh|state' | head -n 250"),
                Triple("dumpsys_surfaceflinger", "SurfaceFlinger", "dumpsys SurfaceFlinger 2>/dev/null | grep -iE 'hbm|lhbm|fod|udfps|dim|layer|display|refresh|hwc|composer' | head -n 250"),
                Triple("dumpsys_input", "input", "dumpsys input 2>/dev/null | grep -iE 'finger|fod|udfps|touch|ts|goodix|fts|gt9|focal|synaptics|novatek|device ' | head -n 250")
            )
            for ((key, serviceName, cmd) in dumpSpecs) {
                if (dumpsysList.isEmpty() || dumpsysList.contains(serviceName)) {
                    val out = shell.exec(cmd, preferRoot = true, timeoutMs = 10_000L).stdout.trim()
                    if (out.isNotBlank()) {
                        liveDumps[key] = out
                        extractDynamicTokens(out, dynamicKeywords)
                    }
                }
            }
            val secServices = shell.exec(
                "lshal --neat -i -t 2>/dev/null | grep -iE 'keystore|keymint|keymaster|gatekeeper|weaver|tee|qsee|trusty|beanpod|kinibi' | head -n 80; " +
                    "service list 2>/dev/null | grep -iE 'keystore|gatekeeper|biometric|fingerprint' | head -n 40",
                preferRoot = true,
                timeoutMs = 8_000L
            ).stdout.trim()
            if (secServices.isNotBlank()) {
                liveDumps["keystore_gatekeeper_tee_services"] = secServices
            }
        } else {
            // Sans Root, ne pas exécuter lshal / dumpsys (qui échouent sans permission DUMP et polluent logcat)
            val vintfFallback = shell.exec(
                "grep -hE 'name>|fqname>|interface' /vendor/etc/vintf/*.xml /vendor/etc/vintf/manifest/*.xml /system/etc/vintf/*.xml 2>/dev/null | grep -iE 'finger|biometric|fod|udfps|display|composer|touch|keystore|keymint|keymaster|gatekeeper|tee' | head -n 140",
                preferRoot = false,
                timeoutMs = 6_000L
            ).stdout.trim()
            if (vintfFallback.isNotBlank()) {
                liveDumps["vintf_statique"] = vintfFallback
                extractDynamicTokens(vintfFallback, dynamicKeywords)
            }
        }

        val activeHalLines = ((liveDumps["lshal_services"] ?: "") + "\n" +
            (liveDumps["service_list"] ?: "") + "\n" +
            (liveDumps["vintf_statique"] ?: ""))
            .lines().filter { it.isNotBlank() }
        emit(2, "Inspection en direct HAL & Services", "${activeHalLines.size} interfaces HAL/Binder/VINTF détectées.")

        // ── PHASE 3 : DÉCOUVERTE DYNAMIQUE SUR PARTITIONS SYSTÈME & VENDOR ────────────
        emit(3, "Découverte dynamique des partitions", "Exploration approfondie de /vendor, /odm, /system, /system_ext, /product, /apex & firmware...")
        val kwRegex = buildDynamicGrepRegex(dynamicKeywords)

        val discoverFilesCmd = """
            for part in /vendor /odm /system /system_ext /product /apex; do
              if [ -d "${'$'}part" ]; then
                find "${'$'}part" -maxdepth 7 \( -type f -o -type l \) 2>/dev/null | grep -iE '$kwRegex' | head -n 220
              fi
            done
            for fw in /vendor/firmware /lib/firmware /vendor/firmware_mnt/image; do
              if [ -d "${'$'}fw" ]; then
                find "${'$'}fw" -maxdepth 3 2>/dev/null | grep -iE 'goodix|gf|fpc|silead|fp|fod|touch|fts|gt9|focal' | head -n 60
              fi
            done
        """.trimIndent()
        val discoveredPaths = shell.exec(discoverFilesCmd, preferRoot = true, timeoutMs = 22_000L)
            .stdout.lines().map { it.trim() }.filter { it.startsWith("/") }.distinct()

        // Scripts init.*.rc, VINTF manifests, ld.config*.txt, overlays & permissions XML
        val configSearchCmd = """
            for part in /vendor/etc /odm/etc /system/etc /system_ext/etc /product/etc; do
              if [ -d "${'$'}part" ]; then
                grep -rliE 'fingerprint|udfps|fod|biometric|goodix|fpc|silead|hbm|lhbm|touchfeature|displayfeature' "${'$'}part/init" "${'$'}part/vintf" "${'$'}part/permissions" 2>/dev/null | head -n 80
              fi
            done
            for ovl in /vendor/overlay /odm/overlay /product/overlay /system_ext/overlay /system/overlay; do
              if [ -d "${'$'}ovl" ]; then
                find "${'$'}ovl" -maxdepth 3 -name '*.apk' 2>/dev/null | head -n 60
              fi
            done
            ls -1 /system/etc/ld.config*.txt /linkerconfig/ld.config.txt /vendor/etc/vintf/*.xml /vendor/etc/vintf/manifest/*.xml /system/etc/vintf/*.xml /system_ext/etc/vintf/*.xml /product/etc/vintf/*.xml 2>/dev/null
        """.trimIndent()
        val configPaths = shell.exec(configSearchCmd, preferRoot = true, timeoutMs = 16_000L)
            .stdout.lines().map { it.trim() }.filter { it.startsWith("/") }.distinct()

        // Index complet des bibliothèques .so avec chemins réels (64-bit & 32-bit) pour résoudre DT_NEEDED
        val libIndexOut = shell.exec(
            "find /vendor/lib64 /vendor/lib /odm/lib64 /odm/lib /system_ext/lib64 /system_ext/lib /product/lib64 /system/lib64 /system/lib /apex -maxdepth 5 \\( -type f -o -type l \\) -name '*.so' 2>/dev/null",
            preferRoot = true,
            timeoutMs = 14_000L
        ).stdout
        val allSoPaths = libIndexOut.lines().map { it.trim() }.filter { it.startsWith("/") && it.endsWith(".so") }
        val soMap64 = LinkedHashMap<String, String>()
        val soMap32 = LinkedHashMap<String, String>()
        val combinedSoMap = LinkedHashMap<String, String>()
        for (soPath in allSoPaths) {
            val baseName = soPath.substringAfterLast('/')
            if (soPath.contains("lib64") || !soPath.contains("/lib/")) {
                soMap64.putIfAbsent(baseName, soPath)
            } else {
                soMap32.putIfAbsent(baseName, soPath)
            }
            combinedSoMap.putIfAbsent(baseName, soPath)
        }
        // Compléter chaque map avec l'autre en fallback
        combinedSoMap.forEach { (k, v) ->
            soMap64.putIfAbsent(k, v)
            soMap32.putIfAbsent(k, v)
        }

        val allCandidateFiles = (discoveredPaths + configPaths).distinct().take(380)
        emit(3, "Découverte dynamique des partitions", "${allCandidateFiles.size} fichiers candidats & ${combinedSoMap.size} bibliothèques .so indexées (${allSoPaths.size} chemins).")

        // ── PHASE 4 : ANALYSE BINAIRE ELF & RÉSOLUTION RÉCURSIVE DT_NEEDED ───────────
        emit(4, "Inspection ELF & dépendances récursives", "Extraction et reconstruction quasi-C++ des binaires HAL et dépendances DT_NEEDED...")
        val seedElfCandidates = (allCandidateFiles.filter { path ->
            path.endsWith(".so") || path.contains("/bin/") || path.contains("/hw/")
        } + allSoPaths.filter { p ->
            val l = p.lowercase()
            l.contains("fingerprint") || l.contains("udfps") || l.contains("fod") ||
                l.contains("goodix") || l.contains("gf_") || l.contains("fpc") ||
                l.contains("silead") || l.contains("egistec") || l.contains("biometric") ||
                l.contains("displayfeature") || l.contains("touchfeature")
        }).distinct()

        val elfQueue = ArrayDeque<Pair<String, Int>>()
        val queuedOrVisitedElf = HashSet<String>()
        seedElfCandidates.forEach { p ->
            if (queuedOrVisitedElf.add(p)) elfQueue.add(p to 0)
        }

        val maxElfAnalyze = if (deepBinaryInspection) 140 else 45
        var analyzedElfCount = 0

        while (elfQueue.isNotEmpty() && analyzedElfCount < maxElfAnalyze) {
            val (path, depth) = elfQueue.removeFirst()
            if (BiometricPrivacyGuard.isProtectedBiometricPath(path)) {
                exclusions.add(BiometricPrivacyGuard.explainExclusion(path))
                continue
            }

            val statLine = shell.exec("ls -ldZ ${RootShellExecutor.shellQuote(path)} 2>/dev/null", preferRoot = true).stdout.trim()
            if (statLine.isBlank()) continue
            val (perms, selinuxCtx) = DeviceTreeAndSysfsProbe.parseLsZ(statLine)
            val sha = shell.computeSha256Safe(path, preferRoot = true)
            val bytes = shell.readFileBytesSafe(path, maxBytes = 14 * 1024 * 1024, preferRoot = true) ?: continue
            analyzedElfCount++

            val targetSoMap = if (path.contains("/lib/") && !path.contains("lib64")) soMap32 else soMap64
            val elfInfo = ElfAnalyzer.analyze(
                bytes = bytes,
                availableLibraries = targetSoMap,
                dynamicKeywords = dynamicKeywords,
                sourcePath = path
            )

            val layer = classifyLayer(path)
            val isOem = isOemSpecificPath(path)
            val summary = if (elfInfo != null) {
                buildString {
                    append("${elfInfo.machine} • ${elfInfo.neededLibraries.size} DT_NEEDED")
                    if (depth > 0) append(" (dép. niv.$depth)")
                    append(" (${elfInfo.missingLibraries.size} manquantes) • ${elfInfo.exportedSymbols.size} exports / ${elfInfo.fodSymbols.size} FOD")
                }
            } else {
                "Exécutable / Bibliothèque système (${bytes.size} octets)"
            }

            val pseudoCppPath = if (elfInfo != null && elfInfo.pseudoSourceCode.isNotBlank()) {
                "quasi_code_source/elf/${sanitizeArtifactFileName(path)}.cpp"
            } else {
                null
            }
            val extractedRel = if (!isGenericSystemBaseLib(path.substringAfterLast('/'))) {
                "fichiers_extraits/${path.removePrefix("/")}"
            } else {
                null
            }

            artifacts.add(
                DiscoveredArtifact(
                    id = "art_${artifacts.size}_${path.hashCode()}",
                    path = path,
                    layer = layer,
                    kind = when {
                        depth > 0 && path.endsWith(".so") -> "Dépendance ELF niv.$depth (.so)"
                        path.endsWith(".so") -> "Bibliothèque ELF (.so)"
                        else -> "Binaire / Service HAL"
                    },
                    sha256 = sha,
                    sizeBytes = bytes.size.toLong(),
                    permissions = perms,
                    seLinuxContext = selinuxCtx,
                    summary = summary,
                    isOemPatch = isOem,
                    elfAnalysis = elfInfo,
                    extractedRelativePath = extractedRel,
                    pseudoSourcePath = pseudoCppPath
                )
            )

            if (elfInfo != null) {
                if (elfInfo.missingLibraries.isNotEmpty()) {
                    anomalies.add(
                        FodAnomaly(
                            id = "anom_elf_${anomalies.size}",
                            title = "Dépendance ELF introuvable dans ${path.substringAfterLast('/')}",
                            severity = SeverityLevel.CRITIQUE,
                            layer = layer,
                            evidence = "Bibliothèques DT_NEEDED absentes : ${elfInfo.missingLibraries.joinToString(", ")} (dans $path)",
                            impact = "Le service ou HAL biométrique ne peut pas être chargé par le linker dynamique sur ce système/GSI.",
                            portingAction = "Vérifier /vendor/etc/ld.config.txt (namespace VNDK/vendor) ou porter les .so manquants : ${elfInfo.missingLibraries.joinToString(", ")}."
                        )
                    )
                }

                // Traversée récursive des dépendances DT_NEEDED (jusqu'à profondeur 4)
                if (depth < 4) {
                    elfInfo.resolvedDependencies.forEach { (depName, depPath) ->
                        if (!isGenericSystemBaseLib(depName) && queuedOrVisitedElf.add(depPath)) {
                            elfQueue.add(depPath to (depth + 1))
                        }
                    }
                }
            }
        }
        emit(4, "Inspection ELF & dépendances récursives", "$analyzedElfCount binaires & dépendances ELF inspectés en profondeur.")

        // ── PHASE 5 : INSPECTION À FROID DEX / APK / JAR / RRO & CONFIGS ─────────────
        emit(5, "Inspection DEX, RRO & configurations", "Décodage AXML, Dalvik DEX, init.rc et manifestes (aucune modification d'APK)...")
        val apkJarCandidates = (allCandidateFiles.filter {
            it.endsWith(".apk") || it.endsWith(".jar")
        } + listOf(
            "/system_ext/priv-app/SystemUI/SystemUI.apk",
            "/system/priv-app/SystemUI/SystemUI.apk",
            "/product/priv-app/SystemUI/SystemUI.apk",
            "/system/framework/framework.jar",
            "/system/framework/services.jar",
            "/system/framework/framework-res.apk"
        )).distinct().take(if (deepBinaryInspection) 40 else 14)

        for (path in apkJarCandidates) {
            val existsRes = shell.exec("[ -f ${RootShellExecutor.shellQuote(path)} ] && ls -ldZ ${RootShellExecutor.shellQuote(path)} 2>/dev/null", preferRoot = true)
            if (existsRes.stdout.isBlank()) continue
            val (perms, selinuxCtx) = DeviceTreeAndSysfsProbe.parseLsZ(existsRes.stdout.trim())
            val sha = shell.computeSha256Safe(path, preferRoot = true)
            val bytes = shell.readFileBytesSafe(path, maxBytes = 24 * 1024 * 1024, preferRoot = true)
            val dexRro = if (bytes != null) DexAndRroAnalyzer.analyzeApkOrJarBytes(path, bytes, dynamicKeywords) else null

            if (dexRro != null) {
                val isRro = dexRro.rroTargetPackage != null || path.contains("overlay", true)
                val summary = buildString {
                    if (dexRro.rroTargetPackage != null) {
                        append("RRO → ${dexRro.rroTargetPackage} (priorité ${dexRro.rroPriority ?: "?"}) • ")
                    }
                    append("${dexRro.matchedClasses.size} classes • ${dexRro.matchedMethods.size} méthodes • ${dexRro.matchedConfigKeys.size} clés config")
                }
                val pseudoPath = when {
                    dexRro.pseudoSourceCode.isNotBlank() -> "quasi_code_source/dex_java/${sanitizeArtifactFileName(path)}.java"
                    dexRro.decodedRroXml.isNotBlank() -> "quasi_code_source/rro_xml/${sanitizeArtifactFileName(path)}.xml"
                    else -> null
                }
                val extractRel = if (isRro || path.contains("SystemUI", true) || path.contains("fingerprint", true) || path.contains("biometric", true)) {
                    "fichiers_extraits/${path.removePrefix("/")}"
                } else {
                    null
                }
                artifacts.add(
                    DiscoveredArtifact(
                        id = "art_${artifacts.size}_${path.hashCode()}",
                        path = path,
                        layer = if (path.startsWith("/vendor") || path.startsWith("/odm")) SystemLayer.VENDOR else SystemLayer.FRAMEWORK,
                        kind = if (isRro) "Overlay RRO (lecture seule)" else "Archive DEX/APK/JAR (lecture seule)",
                        sha256 = sha,
                        sizeBytes = bytes?.size?.toLong() ?: 0L,
                        permissions = perms,
                        seLinuxContext = selinuxCtx,
                        summary = summary,
                        isOemPatch = isOemSpecificPath(path) || isRro,
                        dexRroAnalysis = dexRro,
                        extractedRelativePath = extractRel,
                        pseudoSourcePath = pseudoPath
                    )
                )
            }
        }

        // Fichiers texte init.rc, vintf, linker, permissions
        val textConfigFiles = allCandidateFiles.filter {
            it.endsWith(".rc") || it.endsWith(".xml") || it.endsWith(".txt") || it.endsWith(".conf") || it.endsWith(".prop")
        }.take(100)

        for (path in textConfigFiles) {
            if (BiometricPrivacyGuard.isProtectedBiometricPath(path)) {
                exclusions.add(BiometricPrivacyGuard.explainExclusion(path))
                continue
            }
            val statLine = shell.exec("ls -ldZ ${RootShellExecutor.shellQuote(path)} 2>/dev/null", preferRoot = true).stdout.trim()
            val (perms, selinuxCtx) = DeviceTreeAndSysfsProbe.parseLsZ(statLine)
            val sha = shell.computeSha256Safe(path, preferRoot = true)
            val rawBytes = shell.readFileBytesSafe(path, maxBytes = 768 * 1024, preferRoot = true)
            val content = rawBytes?.toString(Charsets.UTF_8).orEmpty()

            val excerptText = if (path.endsWith(".rc")) {
                extractRelevantInitRcBlocks(content)
            } else {
                content.lines()
                    .filter { line ->
                        val l = line.lowercase()
                        l.contains("finger") || l.contains("udfps") || l.contains("fod") ||
                            l.contains("biometric") || l.contains("hbm") || l.contains("lhbm") ||
                            l.contains("goodix") || l.contains("fpc") || l.contains("silead") ||
                            l.contains("touch") || l.contains("display")
                    }
                    .take(80)
                    .joinToString("\n")
            }

            if (excerptText.isNotBlank() || path.contains("vintf") || path.contains("ld.config")) {
                val finalExcerpt = excerptText.ifBlank { content.take(4000) }
                val pseudoCfgPath = when {
                    path.endsWith(".rc") -> "quasi_code_source/init/${sanitizeArtifactFileName(path)}"
                    path.endsWith(".xml") -> "quasi_code_source/xml/${sanitizeArtifactFileName(path)}"
                    else -> "quasi_code_source/configs/${sanitizeArtifactFileName(path)}"
                }
                artifacts.add(
                    DiscoveredArtifact(
                        id = "art_${artifacts.size}_${path.hashCode()}",
                        path = path,
                        layer = classifyLayer(path),
                        kind = when {
                            path.endsWith(".rc") -> "Script Init (.rc)"
                            path.contains("vintf") -> "Manifeste / Matrice VINTF"
                            path.contains("ld.config") -> "Configuration Linker"
                            else -> "Fichier de configuration"
                        },
                        sha256 = sha,
                        sizeBytes = rawBytes?.size?.toLong() ?: 0L,
                        permissions = perms,
                        seLinuxContext = selinuxCtx,
                        summary = "${finalExcerpt.lines().size} lignes FOD/HAL pertinentes extraites",
                        isOemPatch = isOemSpecificPath(path),
                        rawExcerpt = finalExcerpt,
                        extractedRelativePath = "fichiers_extraits/${path.removePrefix("/")}",
                        pseudoSourcePath = pseudoCfgPath
                    )
                )
            }
        }

        // ── PHASE 6 : NOYAU, DEVICE TREE, SYSFS, DISPLAY & TACTILE ────────────────────
        emit(6, "Noyau, Device Tree, Display & Tactile", "Exploration de /proc/device-tree, /sys, /dev, getevent, /proc/interrupts et dmesg...")
        val dtNodes = dtAndSysfs.probeDeviceTree(dynamicKeywords)
        for (dt in dtNodes) {
            artifacts.add(
                DiscoveredArtifact(
                    id = "art_${artifacts.size}_${dt.nodePath.hashCode()}",
                    path = dt.nodePath,
                    layer = SystemLayer.DEVICE_TREE,
                    kind = "Nœud Device Tree (FDT)",
                    sha256 = sha256Text(dt.properties.entries.joinToString(";") { "${it.key}=${it.value}" }),
                    sizeBytes = dt.properties.size.toLong(),
                    permissions = "r--r--r--",
                    seLinuxContext = "proc_dt",
                    summary = "compatible=${dt.compatible ?: "non défini"} (${dt.properties.size} propriétés)",
                    isOemPatch = true,
                    deviceTreeNode = dt,
                    rawExcerpt = dt.properties.entries.joinToString("\n") { "${it.key} = ${it.value}" },
                    pseudoSourcePath = if (dt.pseudoDtsi.isNotBlank()) "quasi_code_source/devicetree/${sanitizeArtifactFileName(dt.nodePath)}.dtsi" else null
                )
            )
        }

        val sysfsNodes = dtAndSysfs.probeSysfsAndDev(dynamicKeywords)
        for (sn in sysfsNodes) {
            val layer = when (sn.category) {
                "AFFICHAGE" -> SystemLayer.DISPLAY
                "TACTILE" -> SystemLayer.TOUCH
                else -> SystemLayer.KERNEL
            }
            artifacts.add(
                DiscoveredArtifact(
                    id = "art_${artifacts.size}_${sn.path.hashCode()}",
                    path = sn.path,
                    layer = layer,
                    kind = if (sn.path.startsWith("/dev/")) "Nœud /dev" else "Nœud Sysfs",
                    sha256 = sha256Text("${sn.path}:${sn.readableValue}"),
                    sizeBytes = sn.readableValue.length.toLong(),
                    permissions = sn.permissions,
                    seLinuxContext = sn.seLinuxContext,
                    summary = if (sn.readableValue.isNotBlank()) "Valeur: ${sn.readableValue}" else "Nœud exposé (${sn.permissions})",
                    rawExcerpt = sn.readableValue
                )
            )
        }

        val interruptsOut = shell.exec("cat /proc/interrupts 2>/dev/null | grep -iE 'finger|fod|goodix|fpc|silead|touch|fts|gt9|focal|dsi|disp' | head -n 60", preferRoot = true).stdout
        val modulesOut = shell.exec("cat /proc/modules 2>/dev/null | head -n 120; find /vendor/lib/modules /lib/modules -name '*.ko' 2>/dev/null | head -n 80", preferRoot = true).stdout
        val geteventOut = if (rootInfo.isGranted) {
            shell.exec("getevent -lp 2>/dev/null | grep -iE 'add device|name:|ABS_MT|BTN_FINGERPRINT|KEY_FINGERPRINT|014a|fod|touch' -B 1 -A 2 | head -n 160", preferRoot = true).stdout
        } else {
            ""
        }
        val dmesgOut = if (rootInfo.isGranted) {
            shell.exec("dmesg 2>/dev/null | grep -iE 'finger|fod|udfps|goodix|fpc|silead|hbm|lhbm|panel|dsi|touch|avc:' | tail -n 180", preferRoot = true).stdout
        } else {
            ""
        }
        val logcatOut = if (rootInfo.isGranted) {
            shell.exec("logcat -b all -d 2>/dev/null | grep -iE 'Fingerprint|Biometric|Udfps|FOD|goodix|fpc|silead|HBM|LHBM|DisplayFeature|TouchFeature|avc: denied' | tail -n 220", preferRoot = true).stdout
        } else {
            ""
        }

        if (interruptsOut.isNotBlank()) liveDumps["proc_interrupts"] = interruptsOut
        if (modulesOut.isNotBlank()) liveDumps["kernel_modules"] = modulesOut
        if (geteventOut.isNotBlank()) liveDumps["getevent_lp"] = geteventOut
        if (dmesgOut.isNotBlank()) liveDumps["dmesg_fod"] = dmesgOut
        if (logcatOut.isNotBlank()) liveDumps["logcat_fod"] = logcatOut

        // ── PHASE 7 : AUDIT SELINUX & REFUS AVC ───────────────────────────────────────
        emit(7, "Audit SELinux & Contextes", "Analyse des politiques CIL, *_contexts et refus avc: denied...")
        val seLogs = ((dmesgOut) + "\n" + (logcatOut)).lines()
            .filter { it.contains("avc: denied", ignoreCase = true) }
            .distinct()
            .take(80)

        val teRules = LinkedHashSet<String>()
        for (line in seLogs) {
            val domain = Regex("scontext=u:r:([^:]+):").find(line)?.groupValues?.getOrNull(1)
            val target = Regex("tcontext=u:[^:]+:([^:]+):").find(line)?.groupValues?.getOrNull(1)
            val tclass = Regex("tclass=([^\\s]+)").find(line)?.groupValues?.getOrNull(1)
            val perm = Regex("\\{\\s*([^}]+)\\s*\\}").find(line)?.groupValues?.getOrNull(1)?.trim()

            if (!domain.isNullOrBlank() && !target.isNullOrBlank() && !tclass.isNullOrBlank() && !perm.isNullOrBlank()) {
                teRules.add("allow $domain $target:$tclass { $perm };")
            }

            selinuxFindings.add(
                SelinuxFinding(
                    sourceType = "AVC_DENIED",
                    rawLine = line,
                    domain = domain,
                    targetType = target,
                    tclass = tclass,
                    permission = perm
                )
            )
        }

        if (teRules.isNotEmpty()) {
            liveDumps["sepolicy_fod_rules_te"] = "# Règles SELinux synthétisées depuis avc: denied\n" + teRules.joinToString("\n")
        }

        if (seLogs.isNotEmpty()) {
            anomalies.add(
                FodAnomaly(
                    id = "anom_selinux_avc",
                    title = "${seLogs.size} refus SELinux (avc: denied) liés au FOD/Affichage/Tactile",
                    severity = SeverityLevel.CRITIQUE,
                    layer = SystemLayer.SELINUX,
                    evidence = seLogs.take(4).joinToString("\n"),
                    impact = "En mode $seLinuxMode, ces refus bloquent l'accès du HAL biométrique ou de SystemUI aux nœuds sysfs/ioctl/services vendor.",
                    portingAction = "Ajouter les règles générées dans quasi_code_source/fod_sepolicy.te :\n${teRules.take(6).joinToString("\n")}"
                )
            )
        }

        val ctxFilesOut = shell.exec(
            "grep -rnE 'finger|fod|udfps|goodix|fpc|silead|hbm|lhbm|biometric|fpdata|keystore|keymint|gatekeeper|tee' /vendor/etc/selinux /system/etc/selinux /system_ext/etc/selinux /product/etc/selinux /odm/etc/selinux 2>/dev/null | head -n 140",
            preferRoot = true,
            timeoutMs = 10_000L
        ).stdout
        if (ctxFilesOut.isNotBlank()) {
            liveDumps["selinux_contexts"] = ctxFilesOut
            ctxFilesOut.lines().take(65).forEach { line ->
                selinuxFindings.add(
                    SelinuxFinding(
                        sourceType = "CONTEXT_POLICY",
                        rawLine = line,
                        domain = null,
                        targetType = line.substringAfter("u:object_r:").substringBefore(":").takeIf { line.contains("u:object_r:") },
                        tclass = null,
                        permission = null
                    )
                )
            }
        }

        // Audit structurel métadonnées SEULEMENT (permissions, UID/GID, contexte SELinux) sur zones biométriques/keystore/TEE
        // Aucun contenu de gabarit d'empreinte ni de clé privée n'est jamais lu.
        val protectedAreaAudits = auditProtectedAreaMetadata(rootInfo.isGranted)
        protectedAreaAudits.forEach { area ->
            exclusions.add("${BiometricPrivacyGuard.explainExclusion(area.path)} [Métadonnées : exists=${area.exists}, perms=${area.permissions}, owner=${area.ownerGroup}, ctx=${area.seLinuxContext}]")
        }

        // ── PHASE 8 : CORRÉLATION FACTUELLE, GRAPHE & RAPPORT COMPLET ─────────────────
        emit(8, "Corrélation, Cartographie & Rapport", "Construction du graphe FOD, détection des ruptures de chaîne et rédaction du rapport...")

        val (nodes, edges) = buildKnowledgeGraphAndCorrelate(
            artifacts = artifacts,
            relevantProps = relevantProps,
            liveDumps = liveDumps,
            selinuxFindings = selinuxFindings,
            anomalies = anomalies,
            isDsuActive = isDsuActive,
            rootGranted = rootInfo.isGranted
        )

        val completenessScore = computeCompletenessScore(nodes, edges, anomalies, rootInfo.isGranted)
        val timestampIso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).format(Date())
        val snapshotId = "SNAP_${Build.MODEL.replace(Regex("[^A-Za-z0-9]"), "_")}_${if (isDsuActive) "GSI" else "STOCK"}_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}_${UUID.randomUUID().toString().take(4)}"

        val metadata = SnapshotMetadata(
            id = snapshotId,
            displayName = "${Build.MANUFACTURER} ${Build.MODEL} (${romType.labelFr})",
            romType = romType,
            isImported = false,
            deviceModel = Build.MODEL ?: "Inconnu",
            deviceManufacturer = Build.MANUFACTURER ?: "Inconnu",
            deviceCodename = allProps["ro.product.device"] ?: Build.DEVICE ?: "Inconnu",
            boardPlatform = allProps["ro.board.platform"] ?: "Inconnu",
            socModel = allProps["ro.soc.model"] ?: allProps["ro.hardware"] ?: "Inconnu",
            androidVersion = Build.VERSION.RELEASE ?: "?",
            sdkInt = Build.VERSION.SDK_INT,
            buildFingerprint = allProps["ro.build.fingerprint"] ?: Build.FINGERPRINT ?: "Inconnu",
            vendorFingerprint = allProps["ro.vendor.build.fingerprint"] ?: "Inconnu",
            kernelVersion = kernelVersion,
            seLinuxMode = seLinuxMode,
            rootGranted = rootInfo.isGranted,
            rootProvider = rootInfo.provider,
            isDsuActive = isDsuActive,
            timestampIso = timestampIso,
            snapshotDirPath = "$databaseDirPath/$snapshotId",
            completenessScore = completenessScore
        )

        val reportMd = generateFullMarkdownReport(
            metadata = metadata,
            relevantProps = relevantProps,
            artifacts = artifacts,
            nodes = nodes,
            edges = edges,
            anomalies = anomalies,
            selinuxFindings = selinuxFindings,
            liveDumps = liveDumps,
            exclusions = exclusions,
            protectedAreaAudits = protectedAreaAudits
        )

        onProgress(
            AnalysisProgress(
                isRunning = false,
                currentPhaseIndex = 8,
                totalPhases = 8,
                currentPhaseTitle = "Analyse terminée",
                progressFraction = 1f,
                liveLogs = logs.toList()
            )
        )

        FodSnapshot(
            metadata = metadata,
            artifacts = artifacts,
            nodes = nodes,
            edges = edges,
            anomalies = anomalies,
            properties = relevantProps,
            liveDumps = liveDumps,
            selinuxFindings = selinuxFindings,
            biometricExclusions = exclusions.distinct(),
            reportMarkdown = reportMd,
            phaseLogs = logs.toList(),
            protectedAreaAudits = protectedAreaAudits
        )
    }

    private fun buildKnowledgeGraphAndCorrelate(
        artifacts: List<DiscoveredArtifact>,
        relevantProps: Map<String, String>,
        liveDumps: Map<String, String>,
        selinuxFindings: List<SelinuxFinding>,
        anomalies: MutableList<FodAnomaly>,
        isDsuActive: Boolean,
        rootGranted: Boolean
    ): Pair<List<FodNode>, List<FodEdge>> {
        val nodes = mutableListOf<FodNode>()
        val edges = mutableListOf<FodEdge>()

        val fwArtifacts = artifacts.filter { it.layer == SystemLayer.FRAMEWORK }
        val halArtifacts = artifacts.filter { it.layer == SystemLayer.HAL }
        val vendorArtifacts = artifacts.filter { it.layer == SystemLayer.VENDOR }
        val displayArtifacts = artifacts.filter { it.layer == SystemLayer.DISPLAY }
        val touchArtifacts = artifacts.filter { it.layer == SystemLayer.TOUCH }
        val kernelArtifacts = artifacts.filter { it.layer == SystemLayer.KERNEL }
        val dtArtifacts = artifacts.filter { it.layer == SystemLayer.DEVICE_TREE }

        val dumpsysFp = liveDumps["dumpsys_fingerprint"].orEmpty()
        val sdkLive = liveDumps["sdk_live_telemetry"].orEmpty()
        val lshalOut = liveDumps["lshal_services"].orEmpty() + "\n" +
            liveDumps["service_list"].orEmpty() + "\n" +
            liveDumps["vintf_statique"].orEmpty()
        val geteventOut = liveDumps["getevent_lp"].orEmpty()

        val hasUdfpsInFramework = fwArtifacts.any {
            it.dexRroAnalysis?.matchedClasses?.any { c -> c.contains("udfps", true) || c.contains("fod", true) } == true ||
                it.dexRroAnalysis?.matchedConfigKeys?.any { k -> k.contains("udfps", true) || k.contains("fod", true) } == true
        } || dumpsysFp.contains("udfps", true) || dumpsysFp.contains("TYPE_UDFPS", true)

        val hasActiveHal = lshalOut.contains("fingerprint", true) ||
            dumpsysFp.contains("SensorId", true) ||
            sdkLive.contains("FEATURE_FINGERPRINT=true")
        val hasBrokenElf = artifacts.any { (it.elfAnalysis?.missingLibraries?.isNotEmpty()) == true }
        val hasDisplayHook = displayArtifacts.isNotEmpty() || relevantProps.keys.any { it.contains("hbm", true) || it.contains("lhbm", true) }
        val hasTouchHook = touchArtifacts.isNotEmpty() ||
            geteventOut.contains("FINGERPRINT", true) ||
            geteventOut.contains("ABS_MT", true) ||
            sdkLive.contains("touch", true)
        val hasKernelDriver = kernelArtifacts.isNotEmpty() || dtArtifacts.isNotEmpty()
        val hasSelinuxAvc = selinuxFindings.any { it.sourceType == "AVC_DENIED" }

        if (!rootGranted) {
            anomalies.add(
                FodAnomaly(
                    id = "anom_no_root",
                    title = "Accès Root (Magisk/SU) non accordé lors de l'analyse",
                    severity = SeverityLevel.AVERTISSEMENT,
                    layer = SystemLayer.SELINUX,
                    evidence = "id n'a pas renvoyé uid=0",
                    impact = "Les nœuds /proc/device-tree, dmesg, certains binaires /vendor et nœuds sysfs protégés n'ont pas pu être lus en totalité.",
                    portingAction = "Activer l'autorisation Root dans Paramètres > Magisk/SU puis relancer LANCER L’ANALYSE FOD."
                )
            )
        }

        if (!hasActiveHal) {
            anomalies.add(
                FodAnomaly(
                    id = "anom_no_hal",
                    title = "Aucun service HAL Fingerprint actif détecté en direct",
                    severity = SeverityLevel.CRITIQUE,
                    layer = SystemLayer.HAL,
                    evidence = "lshal / service list / dumpsys fingerprint ne remontent aucun service HAL biométrique enregistré.",
                    impact = "Android Framework ne reçoit aucun capteur biométrique utilisable (le lecteur FOD n'apparaît pas).",
                    portingAction = "Inspecter le service init.*.rc du HAL fingerprint, les bibliothèques DT_NEEDED et les refus SELinux au démarrage."
                )
            )
        }

        if (!hasUdfpsInFramework) {
            anomalies.add(
                FodAnomaly(
                    id = "anom_no_udfps_fw",
                    title = "Configuration UDFPS / Overlay FOD absente ou incomplète côté Framework/SystemUI",
                    severity = if (isDsuActive) SeverityLevel.CRITIQUE else SeverityLevel.AVERTISSEMENT,
                    layer = SystemLayer.FRAMEWORK,
                    evidence = "Aucune classe/config UDFPS complète ou RRO SystemUI/framework-res détectée pour le capteur sous écran.",
                    impact = "Même si le HAL répond, SystemUI n'affiche pas l'icône FOD ni le cercle d'illumination aux bonnes coordonnées.",
                    portingAction = "Comparer les clés RRO (config_udfps*, sensorLocation) et les classes UdfpsHandler entre la ROM d'origine et le GSI."
                )
            )
        }

        if (!hasDisplayHook) {
            anomalies.add(
                FodAnomaly(
                    id = "anom_no_hbm",
                    title = "Mécanisme d'illumination HBM/LHBM introuvable dans les nœuds affichage",
                    severity = SeverityLevel.AVERTISSEMENT,
                    layer = SystemLayer.DISPLAY,
                    evidence = "Aucun nœud sysfs/DRM HBM, LHBM ou disp_param identifié.",
                    impact = "Pour un capteur optique, l'absence de passage en High Brightness Mode (HBM/LHBM) empêche la lecture de l'empreinte.",
                    portingAction = "Comparer les nœuds /sys/class/drm ou /sys/class/backlight et les appels SurfaceFlinger/HWC avec la ROM d'origine."
                )
            )
        }

        if (!hasTouchHook) {
            anomalies.add(
                FodAnomaly(
                    id = "anom_no_touch",
                    title = "Signalisation tactile FOD (fod_status / BTN_FINGERPRINT) non détectée",
                    severity = SeverityLevel.AVERTISSEMENT,
                    layer = SystemLayer.TOUCH,
                    evidence = "Aucun nœud tactile FOD ni événement BTN_FINGERPRINT relevé dans getevent/sysfs.",
                    impact = "Le contrôleur tactile ou le HAL peut ne pas notifier le capteur lorsque le doigt appuie sur la zone FOD.",
                    portingAction = "Vérifier l'interface tactile constructeur (ex: ITouchFeature, fod_status, gpio/irq) dans la capture ROM d'origine."
                )
            )
        }

        val oemRros = fwArtifacts.filter { it.dexRroAnalysis?.rroTargetPackage != null } +
            vendorArtifacts.filter { it.dexRroAnalysis?.rroTargetPackage != null }
        if (oemRros.isNotEmpty()) {
            anomalies.add(
                FodAnomaly(
                    id = "anom_oem_rro",
                    title = "${oemRros.size} surcharge(s) RRO constructeur détectée(s)",
                    severity = SeverityLevel.INFO,
                    layer = SystemLayer.FRAMEWORK,
                    evidence = oemRros.joinToString("\n") { "${it.path} -> cible ${it.dexRroAnalysis?.rroTargetPackage}" },
                    impact = "Ces RRO injectent souvent les coordonnées du capteur et les paramètres UDFPS dans SystemUI/framework-res.",
                    portingAction = "Vérifier leur présence, signature/priorité et clés resources.arsc dans le GSI cible."
                )
            )
        }

        nodes.add(
            FodNode(
                id = "node_framework",
                label = "SystemUI & Framework UDFPS",
                layer = SystemLayer.FRAMEWORK,
                status = if (hasUdfpsInFramework) NodeStatus.ACTIF else NodeStatus.MANQUANT,
                details = "${fwArtifacts.size} artefacts Framework/RRO • ${if (hasUdfpsInFramework) "UDFPS détecté" else "UDFPS non détecté"}",
                artifactPath = fwArtifacts.firstOrNull()?.path
            )
        )
        nodes.add(
            FodNode(
                id = "node_hal",
                label = "HAL Biométrique (AIDL/HIDL)",
                layer = SystemLayer.HAL,
                status = when {
                    hasBrokenElf -> NodeStatus.CASSE
                    hasActiveHal -> NodeStatus.ACTIF
                    else -> NodeStatus.MANQUANT
                },
                details = "${halArtifacts.size} artefacts HAL • ${if (hasActiveHal) "Service enregistré" else "Service absent"}",
                artifactPath = halArtifacts.firstOrNull()?.path
            )
        )
        nodes.add(
            FodNode(
                id = "node_vendor",
                label = "Vendor Blobs, Init & ELF",
                layer = SystemLayer.VENDOR,
                status = when {
                    hasBrokenElf -> NodeStatus.CASSE
                    vendorArtifacts.any { it.isOemPatch } -> NodeStatus.PATCH_CONSTRUCTEUR
                    vendorArtifacts.isNotEmpty() -> NodeStatus.ACTIF
                    else -> NodeStatus.MANQUANT
                },
                details = "${vendorArtifacts.size} artefacts Vendor • ${artifacts.sumOf { it.elfAnalysis?.missingLibraries?.size ?: 0 }} DT_NEEDED manquantes",
                artifactPath = vendorArtifacts.firstOrNull()?.path
            )
        )
        nodes.add(
            FodNode(
                id = "node_display",
                label = "Affichage OLED / HBM / LHBM",
                layer = SystemLayer.DISPLAY,
                status = if (hasDisplayHook) NodeStatus.ACTIF else NodeStatus.MANQUANT,
                details = "${displayArtifacts.size} nœuds affichage/DRM/backlight",
                artifactPath = displayArtifacts.firstOrNull()?.path
            )
        )
        nodes.add(
            FodNode(
                id = "node_touch",
                label = "Contrôleur Tactile & Events",
                layer = SystemLayer.TOUCH,
                status = if (hasTouchHook) NodeStatus.ACTIF else NodeStatus.MANQUANT,
                details = "${touchArtifacts.size} nœuds tactiles & événements input",
                artifactPath = touchArtifacts.firstOrNull()?.path
            )
        )
        nodes.add(
            FodNode(
                id = "node_kernel",
                label = "Noyau, Sysfs & Pilotes",
                layer = SystemLayer.KERNEL,
                status = if (hasKernelDriver) NodeStatus.ACTIF else NodeStatus.PROTEGE,
                details = "${kernelArtifacts.size} nœuds noyau/sysfs/dev",
                artifactPath = kernelArtifacts.firstOrNull()?.path
            )
        )
        nodes.add(
            FodNode(
                id = "node_dt",
                label = "Device Tree (FDT)",
                layer = SystemLayer.DEVICE_TREE,
                status = if (dtArtifacts.isNotEmpty()) NodeStatus.ACTIF else if (rootGranted) NodeStatus.MANQUANT else NodeStatus.PROTEGE,
                details = "${dtArtifacts.size} nœuds Device Tree découverts",
                artifactPath = dtArtifacts.firstOrNull()?.path
            )
        )
        nodes.add(
            FodNode(
                id = "node_selinux",
                label = "Politique SELinux",
                layer = SystemLayer.SELINUX,
                status = if (hasSelinuxAvc) NodeStatus.CASSE else NodeStatus.ACTIF,
                details = "${selinuxFindings.count { it.sourceType == "AVC_DENIED" }} refus AVC • ${selinuxFindings.count { it.sourceType == "CONTEXT_POLICY" }} contextes",
                artifactPath = null
            )
        )

        edges.add(FodEdge("node_framework", "node_hal", "Binder / AIDL / HIDL", !hasActiveHal || !hasUdfpsInFramework, if (hasActiveHal) "Service biométrique enregistré" else "Interface HAL inactive"))
        edges.add(FodEdge("node_framework", "node_display", "Illumination HBM / Dim Layer", !hasDisplayHook, if (hasDisplayHook) "Chemins HBM/SurfaceFlinger présents" else "Aucun contrôle HBM détecté"))
        edges.add(FodEdge("node_framework", "node_touch", "Notification appui doigt", !hasTouchHook, if (hasTouchHook) "Événements/sysfs tactiles trouvés" else "Lien tactile FOD absent"))
        edges.add(FodEdge("node_hal", "node_vendor", "Linker ELF & Init .rc", hasBrokenElf || vendorArtifacts.isEmpty(), if (hasBrokenElf) "DT_NEEDED manquantes" else "Chaîne ELF résolue"))
        edges.add(FodEdge("node_vendor", "node_kernel", "Ioctl / Sysfs / /dev", !hasKernelDriver, "${kernelArtifacts.size} nœuds noyau accessibles"))
        edges.add(FodEdge("node_kernel", "node_dt", "Sondes pilotes FDT", dtArtifacts.isEmpty(), "${dtArtifacts.size} nœuds Device Tree"))
        edges.add(FodEdge("node_selinux", "node_hal", "Transition domaine & allow", hasSelinuxAvc, if (hasSelinuxAvc) "Refus avc: denied actifs" else "Aucun refus AVC FOD relevé"))

        return nodes to edges
    }

    private fun computeCompletenessScore(
        nodes: List<FodNode>,
        edges: List<FodEdge>,
        anomalies: List<FodAnomaly>,
        rootGranted: Boolean
    ): Int {
        var score = 100
        score -= anomalies.count { it.severity == SeverityLevel.CRITIQUE } * 18
        score -= anomalies.count { it.severity == SeverityLevel.AVERTISSEMENT } * 8
        score -= edges.count { it.isBroken } * 5
        if (!rootGranted) score -= 12
        val activeNodes = nodes.count { it.status == NodeStatus.ACTIF || it.status == NodeStatus.PATCH_CONSTRUCTEUR }
        if (activeNodes == 0) score = minOf(score, 20)
        return score.coerceIn(5, 100)
    }

    private fun generateFullMarkdownReport(
        metadata: SnapshotMetadata,
        relevantProps: Map<String, String>,
        artifacts: List<DiscoveredArtifact>,
        nodes: List<FodNode>,
        edges: List<FodEdge>,
        anomalies: List<FodAnomaly>,
        selinuxFindings: List<SelinuxFinding>,
        liveDumps: Map<String, String>,
        exclusions: List<String>,
        protectedAreaAudits: List<ProtectedAreaMetadata>
    ): String {
        val sb = StringBuilder()
        sb.appendLine("# RAPPORT COMPLET D'INVESTIGATION FOD — FOD LAB INTELLIGENCE")
        sb.appendLine()
        sb.appendLine("> Généré par le moteur factuel déterministe le `${metadata.timestampIso}` (aucune modification d'APK effectuée).")
        sb.appendLine()
        sb.appendLine("## 1. Identité de l'environnement analysé")
        sb.appendLine("- **Identifiant de capture** : `${metadata.id}`")
        sb.appendLine("- **Type de système** : **${metadata.romType.labelFr}** (DSU actif : `${metadata.isDsuActive}`)")
        sb.appendLine("- **Appareil** : `${metadata.deviceManufacturer} ${metadata.deviceModel}` (codename: `${metadata.deviceCodename}`)")
        sb.appendLine("- **Plateforme / SoC** : `${metadata.boardPlatform}` / `${metadata.socModel}`")
        sb.appendLine("- **Android / SDK** : `Android ${metadata.androidVersion} (API ${metadata.sdkInt})`")
        sb.appendLine("- **Empreinte Système** : `${metadata.buildFingerprint}`")
        sb.appendLine("- **Empreinte Vendor** : `${metadata.vendorFingerprint}`")
        sb.appendLine("- **Noyau** : `${metadata.kernelVersion}`")
        sb.appendLine("- **SELinux** : `${metadata.seLinuxMode}` | **Root** : `${metadata.rootProvider}` (`${metadata.rootGranted}`)")
        sb.appendLine("- **Score d'intégrité chaîne FOD** : **${metadata.completenessScore}/100**")
        sb.appendLine()

        sb.appendLine("## 2. Cartographie des couches FOD & liens de dépendance")
        nodes.forEach { n ->
            sb.appendLine("- **[${n.status.labelFr}]** `${n.layer.labelFr}` — *${n.label}* : ${n.details}")
        }
        sb.appendLine()
        sb.appendLine("### Relations inter-couches")
        edges.forEach { e ->
            val state = if (e.isBroken) "RUPTURE" else "OK"
            sb.appendLine("- `[$state]` `${e.fromId}` ──(${e.relation})──▶ `${e.toId}` : ${e.evidence}")
        }
        sb.appendLine()

        sb.appendLine("## 3. Anomalies factuelles & pistes de portage")
        if (anomalies.isEmpty()) {
            sb.appendLine("- Aucune anomalie critique ou rupture de dépendance relevée sur cet environnement.")
        } else {
            anomalies.forEachIndexed { idx, a ->
                sb.appendLine("### ${idx + 1}. [${a.severity.labelFr}] ${a.title} (${a.layer.labelFr})")
                sb.appendLine("- **Preuve brute** :\n```text\n${a.evidence}\n```")
                sb.appendLine("- **Impact technique** : ${a.impact}")
                sb.appendLine("- **Action de portage recommandée** : ${a.portingAction}")
                sb.appendLine()
            }
        }

        sb.appendLine("## 4. Inventaire détaillé des artefacts, SHA-256, ELF & DEX/RRO (${artifacts.size})")
        artifacts.forEach { art ->
            sb.appendLine("### `${art.path}`")
            sb.appendLine("- **Couche** : ${art.layer.labelFr} | **Type** : ${art.kind} ${if (art.isOemPatch) "| **Patch constructeur détecté**" else ""}")
            sb.appendLine("- **SHA-256** : `${art.sha256}` | **Permissions** : `${art.permissions}` | **SELinux** : `${art.seLinuxContext}`")
            art.extractedRelativePath?.let { sb.appendLine("- **Fichier extrait** : `$it`") }
            art.pseudoSourcePath?.let { sb.appendLine("- **Quasi-code source généré** : `$it`") }
            sb.appendLine("- **Résumé** : ${art.summary}")
            art.elfAnalysis?.let { elf ->
                sb.appendLine("- **ELF DT_NEEDED (${elf.neededLibraries.size})** : `${elf.neededLibraries.joinToString(", ")}`")
                if (elf.resolvedDependencies.isNotEmpty()) {
                    sb.appendLine("- **Dépendances résolues** : ${elf.resolvedDependencies.entries.take(20).joinToString(" | ") { "${it.key} -> `${it.value}`" }}")
                }
                if (elf.missingLibraries.isNotEmpty()) {
                    sb.appendLine("- **ELF MANQUANTES** : `${elf.missingLibraries.joinToString(", ")}`")
                }
                if (elf.exportedSymbols.isNotEmpty()) {
                    sb.appendLine("- **Symboles exportés (.dynsym)** : `${elf.exportedSymbols.take(20).joinToString(", ")}`")
                }
                if (elf.importedSymbols.isNotEmpty()) {
                    sb.appendLine("- **Symboles importés (UND)** : `${elf.importedSymbols.take(20).joinToString(", ")}`")
                }
                if (elf.fodStrings.isNotEmpty()) {
                    sb.appendLine("- **Chaînes FOD (.rodata)** : `${elf.fodStrings.take(20).joinToString(" | ")}`")
                }
                if (elf.pseudoSourceCode.isNotBlank()) {
                    sb.appendLine("```cpp\n${elf.pseudoSourceCode.take(2200)}\n```")
                }
            }
            art.dexRroAnalysis?.let { dr ->
                dr.packageName?.let { sb.appendLine("- **Package** : `$it`") }
                dr.rroTargetPackage?.let { sb.appendLine("- **Cible RRO** : `$it` (priorité: `${dr.rroPriority}`)") }
                if (dr.matchedClasses.isNotEmpty()) {
                    sb.appendLine("- **Classes DEX FOD/UDFPS** : `${dr.matchedClasses.take(25).joinToString(", ")}`")
                }
                if (dr.matchedMethods.isNotEmpty()) {
                    sb.appendLine("- **Méthodes DEX clés** : `${dr.matchedMethods.take(25).joinToString(", ")}`")
                }
                if (dr.matchedConfigKeys.isNotEmpty()) {
                    sb.appendLine("- **Clés de ressources/config** : `${dr.matchedConfigKeys.take(30).joinToString(", ")}`")
                }
                if (dr.decodedRroXml.isNotBlank()) {
                    sb.appendLine("```xml\n${dr.decodedRroXml.take(1600)}\n```")
                }
                if (dr.pseudoSourceCode.isNotBlank()) {
                    sb.appendLine("```java\n${dr.pseudoSourceCode.take(2000)}\n```")
                }
            }
            art.deviceTreeNode?.let { dt ->
                if (dt.pseudoDtsi.isNotBlank()) {
                    sb.appendLine("```dts\n${dt.pseudoDtsi.take(1500)}\n```")
                }
            }
            if (art.rawExcerpt.isNotBlank()) {
                sb.appendLine("```text\n${art.rawExcerpt.take(1500)}\n```")
            }
            sb.appendLine()
        }

        sb.appendLine("## 5. Propriétés système liées au FOD (${relevantProps.size})")
        sb.appendLine("```properties")
        relevantProps.entries.sortedBy { it.key }.forEach { (k, v) ->
            sb.appendLine("$k=$v")
        }
        sb.appendLine("```")
        sb.appendLine()

        sb.appendLine("## 6. Audit SELinux (${selinuxFindings.size} entrées)")
        if (selinuxFindings.isEmpty()) {
            sb.appendLine("- Aucune entrée SELinux/AVC FOD relevée.")
        } else {
            sb.appendLine("```text")
            selinuxFindings.take(80).forEach { sb.appendLine("[${it.sourceType}] ${it.rawLine}") }
            sb.appendLine("```")
        }
        sb.appendLine()

        sb.appendLine("## 7. Sorties Live (dumpsys / lshal / getevent / dmesg / logcat)")
        liveDumps.forEach { (name, body) ->
            if (name != "getprop_complet" && body.isNotBlank()) {
                sb.appendLine("### $name")
                sb.appendLine("```text")
                sb.appendLine(body.take(4000))
                sb.appendLine("```")
            }
        }

        sb.appendLine("## 8. Audit structurel Biométrie / Keystore / TEE (métadonnées sans lecture de secrets)")
        if (protectedAreaAudits.isEmpty()) {
            sb.appendLine("- Aucune métadonnée de zone protégée collectée.")
        } else {
            protectedAreaAudits.forEach { a ->
                sb.appendLine("- `${a.path}` (${a.category}) : existe=`${a.exists}` | perms=`${a.permissions}` | owner=`${a.ownerGroup}` | SELinux=`${a.seLinuxContext}` | entrées=`${a.entryCount}` — ${a.note}")
            }
        }
        sb.appendLine()
        exclusions.distinct().forEach { sb.appendLine("- $it") }

        return sb.toString()
    }

    private fun parseGetprop(output: String): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        val regex = Regex("^\\[([^]]+)]\\s*:\\s*\\[(.*)]$")
        output.lineSequence().forEach { line ->
            val m = regex.matchEntire(line.trim())
            if (m != null) {
                map[m.groupValues[1]] = m.groupValues[2]
            }
        }
        return map
    }

    private fun extractDynamicTokens(text: String, out: MutableSet<String>) {
        val knownVendors = listOf(
            "goodix", "fpc", "silead", "focaltech", "egistec", "qti", "synaptics",
            "novatek", "xiaomi", "oplus", "oneplus", "samsung", "udfps", "fod",
            "lhbm", "hbm", "disp_param", "gf_fp", "fp_goodix"
        )
        val lower = text.lowercase()
        knownVendors.forEach { if (lower.contains(it)) out.add(it) }
    }

    private fun buildDynamicGrepRegex(dynamicKeywords: Set<String>): String {
        val base = listOf(
            "fingerprint", "udfps", "fod", "biometric", "goodix", "fpc", "silead",
            "focal", "egistec", "hbm", "lhbm", "touchfeature", "displayfeature",
            "systemui", "overlay"
        )
        val combined = (base + dynamicKeywords.filter { it.length >= 4 }).distinct()
        return combined.joinToString("|") { Regex.escape(it) }
    }

    private fun classifyLayer(path: String): SystemLayer {
        val lower = path.lowercase()
        return when {
            lower.contains("selinux") || lower.endsWith(".cil") || lower.contains("_contexts") -> SystemLayer.SELINUX
            lower.contains("/device-tree") -> SystemLayer.DEVICE_TREE
            lower.contains("hbm") || lower.contains("lhbm") || lower.contains("display") ||
                lower.contains("drm") || lower.contains("composer") || lower.contains("hwc") -> SystemLayer.DISPLAY
            lower.contains("touch") || lower.contains("input") || lower.contains("fts") ||
                lower.contains("synaptics") || lower.contains("novatek") -> SystemLayer.TOUCH
            lower.contains("/sys/") || lower.contains("/dev/") || lower.endsWith(".ko") -> SystemLayer.KERNEL
            lower.contains("systemui") || lower.contains("framework") || lower.contains("overlay") ||
                lower.endsWith(".apk") || lower.endsWith(".jar") -> SystemLayer.FRAMEWORK
            lower.contains("/hw/") || lower.contains("hal") || lower.contains("vintf") ||
                lower.contains("biometrics.fingerprint") -> SystemLayer.HAL
            else -> SystemLayer.VENDOR
        }
    }

    private fun isOemSpecificPath(path: String): Boolean {
        val lower = path.lowercase()
        return lower.contains("xiaomi") || lower.contains("miui") || lower.contains("hyperos") ||
            lower.contains("oplus") || lower.contains("oneplus") || lower.contains("realme") ||
            lower.contains("samsung") || lower.contains("sec_") || lower.contains("moto") ||
            lower.contains("asus") || lower.contains("nothing") || lower.contains("lineage") ||
            lower.contains("goodix") || lower.contains("fpc") || lower.contains("silead")
    }

    private fun collectAndroidSdkLiveTelemetry(
        context: Context?,
        liveDumps: MutableMap<String, String>,
        dynamicKeywords: MutableSet<String>
    ) {
        if (context == null) return
        val sb = StringBuilder()
        runCatching {
            val pm = context.packageManager
            val hasFp = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
            sb.appendLine("FEATURE_FINGERPRINT=$hasFp")
        }
        runCatching {
            val dm = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
            dm?.displays?.forEach { display ->
                val mode = display.mode
                sb.appendLine("Display[${display.displayId}] name=${display.name} mode=${mode.physicalWidth}x${mode.physicalHeight}@${mode.refreshRate}Hz")
            }
        }
        runCatching {
            val im = context.getSystemService(Context.INPUT_SERVICE) as? InputManager
            im?.inputDeviceIds?.forEach { id ->
                val dev = im.getInputDevice(id)
                if (dev != null) {
                    val line = "Input[$id] name=${dev.name} descriptor=${dev.descriptor} sources=0x${dev.sources.toString(16)}"
                    sb.appendLine(line)
                    extractDynamicTokens(line, dynamicKeywords)
                }
            }
        }
        val text = sb.toString().trim()
        if (text.isNotBlank()) {
            liveDumps["sdk_live_telemetry"] = text
        }
    }

    private fun isGenericSystemBaseLib(libName: String): Boolean {
        val base = libName.substringAfterLast('/').lowercase()
        val generic = setOf(
            "libc.so", "libm.so", "libdl.so", "libstdc++.so", "libc++.so", "libc++_shared.so",
            "liblog.so", "libz.so", "libandroid.so", "libvndksupport.so", "libdl_android.so",
            "ld-android.so", "libclang_rt.ubsan_standalone-aarch64-android.so"
        )
        return base in generic
    }

    private fun sanitizeArtifactFileName(path: String): String {
        return path.removePrefix("/")
            .replace('/', '_')
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(110)
    }

    private fun extractRelevantInitRcBlocks(content: String): String {
        val lines = content.lines()
        val out = StringBuilder()
        var capturingBlock = false
        var blockBuffer = mutableListOf<String>()

        fun flushIfRelevant() {
            if (blockBuffer.isNotEmpty()) {
                val joined = blockBuffer.joinToString("\n")
                val lower = joined.lowercase()
                if (lower.contains("finger") || lower.contains("udfps") || lower.contains("fod") ||
                    lower.contains("biometric") || lower.contains("goodix") || lower.contains("fpc") ||
                    lower.contains("silead") || lower.contains("hbm") || lower.contains("lhbm") ||
                    lower.contains("touch") || lower.contains("disp_param")
                ) {
                    out.appendLine(joined)
                    out.appendLine()
                }
            }
            blockBuffer = mutableListOf()
        }

        for (line in lines) {
            val trimmed = line.trimStart()
            val isTopLevel = trimmed.isNotEmpty() && !line.startsWith(" ") && !line.startsWith("\t") && !trimmed.startsWith("#")
            if (isTopLevel && (trimmed.startsWith("service ") || trimmed.startsWith("on ") || trimmed.startsWith("import "))) {
                flushIfRelevant()
                capturingBlock = true
                blockBuffer.add(line)
            } else if (capturingBlock) {
                if (trimmed.isEmpty()) {
                    flushIfRelevant()
                    capturingBlock = false
                } else {
                    blockBuffer.add(line)
                }
            } else {
                val lower = trimmed.lowercase()
                if (lower.contains("finger") || lower.contains("fod") || lower.contains("udfps") || lower.contains("goodix") || lower.contains("hbm")) {
                    out.appendLine(line)
                }
            }
            if (out.length > 14_000) break
        }
        flushIfRelevant()
        return out.toString().trim()
    }

    private suspend fun auditProtectedAreaMetadata(rootGranted: Boolean): List<ProtectedAreaMetadata> {
        val targets = listOf(
            "/data/vendor_de/0/fpdata" to "STOCKAGE_BIOMETRIQUE",
            "/data/system/users/0/fpdata" to "STOCKAGE_BIOMETRIQUE",
            "/data/vendor/fingerprint" to "STOCKAGE_BIOMETRIQUE",
            "/data/misc/keystore" to "KEYSTORE",
            "/data/vendor/keystore" to "KEYSTORE",
            "/mnt/vendor/persist/goodix" to "PERSIST_CALIBRATION",
            "/mnt/vendor/persist/fpc" to "PERSIST_CALIBRATION",
            "/mnt/vendor/persist/silead" to "PERSIST_CALIBRATION",
            "/mnt/vendor/persist/biometrics" to "PERSIST_CALIBRATION",
            "/data/vendor/tee" to "TEE_ENVIRONNEMENT",
            "/dev/qseecom" to "NOEUD_TEE",
            "/dev/tee0" to "NOEUD_TEE",
            "/dev/goodix_fp" to "NOEUD_CAPTEUR",
            "/dev/esfp0" to "NOEUD_CAPTEUR"
        )
        val audits = mutableListOf<ProtectedAreaMetadata>()
        for ((path, category) in targets) {
            val q = RootShellExecutor.shellQuote(path)
            val cmd = "if [ -e $q ]; then ls -ldZ $q 2>/dev/null; stat -c '%a|%U:%G' $q 2>/dev/null; if [ -d $q ]; then ls -1A $q 2>/dev/null | wc -l; else echo 1; fi; else echo MISSING; fi"
            val out = shell.exec(cmd, preferRoot = rootGranted, timeoutMs = 4_000L).stdout.trim()
            val lines = out.lines().map { it.trim() }.filter { it.isNotBlank() }
            if (lines.isEmpty() || lines.first() == "MISSING") {
                audits.add(
                    ProtectedAreaMetadata(
                        path = path,
                        category = category,
                        exists = false,
                        permissions = "-",
                        ownerGroup = "-",
                        seLinuxContext = "-",
                        entryCount = 0,
                        note = if (rootGranted) "Chemin absent sur ce système" else "Absent ou masqué sans Root"
                    )
                )
            } else {
                val lsLine = lines.getOrNull(0).orEmpty()
                val (lsPerms, seCtx) = DeviceTreeAndSysfsProbe.parseLsZ(lsLine)
                val statParts = lines.getOrNull(1)?.split('|').orEmpty()
                val octalPerms = statParts.getOrNull(0)?.takeIf { it.isNotBlank() } ?: lsPerms
                val ownerGrp = statParts.getOrNull(1)?.takeIf { it.isNotBlank() } ?: "?"
                val count = lines.getOrNull(2)?.toIntOrNull() ?: 0
                audits.add(
                    ProtectedAreaMetadata(
                        path = path,
                        category = category,
                        exists = true,
                        permissions = "$lsPerms ($octalPerms)",
                        ownerGroup = ownerGrp,
                        seLinuxContext = seCtx,
                        entryCount = count,
                        note = "Audit métadonnées uniquement (contenu biométrique/clé non lu)"
                    )
                )
            }
        }
        return audits
    }

    private fun sha256Text(text: String): String {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return md.digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}

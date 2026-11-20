package com.example.livefod

import com.example.core.BiometricPrivacyGuard
import com.example.core.DeviceTreeAndSysfsProbe
import com.example.core.DexAndRroAnalyzer
import com.example.core.ElfAnalyzer
import com.example.core.RootShellExecutor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

data class LiveExtractionInput(
    val sessionDir: File,
    val discoveredPathsWithReason: Map<String, String>,
    val halProcesses: List<LiveHalProcessSnapshot>,
    val sysfsTransitions: List<LiveSysfsTransition>,
    val timelineEvents: List<LiveInteractionEvent>,
    val beforeProps: Map<String, String>,
    val afterProps: Map<String, String>,
    val beforeLshal: String,
    val afterLshal: String,
    val beforeDumpsys: Map<String, String>,
    val duringDumpsys: Map<String, String>,
    val afterDumpsys: Map<String, String>,
    val avcLines: List<String>,
    val protectedAreasReport: String,
    val dmesgLines: List<String>
)

data class LiveExtractionOutput(
    val extractedFiles: List<LiveExtractedFileRecord>,
    val mechanism: LiveDiscoveredMechanism,
    val patches: List<LiveGeneratedPatch>
)

class LiveFodArtifactExtractor(private val shell: RootShellExecutor) {

    suspend fun extractChainAndReconstructSources(
        input: LiveExtractionInput,
        onStatus: (String) -> Unit
    ): LiveExtractionOutput = withContext(Dispatchers.IO) {
        val rawDir = File(input.sessionDir, "04_artefacts_extraits").apply { mkdirs() }
        val srcDir = File(input.sessionDir, "05_code_source_reconstruit").apply { mkdirs() }

        // 1. Collecter l'index global des bibliothèques disponibles pour résolution DT_NEEDED
        val libIndex = LinkedHashMap<String, String>()
        val libIndexRes = shell.exec(
            "find /vendor/lib64 /vendor/lib /system_ext/lib64 /product/lib64 /system/lib64 /odm/lib64 -maxdepth 3 -name '*.so' 2>/dev/null | head -n 900",
            preferRoot = true,
            timeoutMs = 12_000L
        )
        libIndexRes.stdout.lines().map { it.trim() }.filter { it.startsWith("/") }.forEach { p ->
            val name = p.substringAfterLast('/')
            if (!libIndex.containsKey(name)) libIndex[name] = p
        }

        // 2. Agréger CHAQUE fichier apparu dans la chaîne (processus /maps, /fd, strace, logcat, dumpsys, RRO)
        val candidatePaths = LinkedHashMap<String, String>()
        fun addCandidate(path: String, reason: String) {
            val clean = path.trim().substringBefore(" ").substringBefore("\u0000")
            if (!clean.startsWith("/") || clean.length < 4) return
            if (clean.startsWith("/dev/") || clean.startsWith("/proc/") || clean.startsWith("/sys/")) return
            if (BiometricPrivacyGuard.isProtectedBiometricPath(clean)) return
            if (isGenericNoiseBinary(clean)) return
            val existing = candidatePaths[clean]
            candidatePaths[clean] = if (existing == null) reason else "$existing | $reason"
        }

        input.discoveredPathsWithReason.forEach { (p, r) -> addCandidate(p, r) }

        // Fichiers mappés en RAM et descripteurs ouverts par chaque PID actif de la chaîne
        input.halProcesses.forEach { proc ->
            proc.mappedFiles.forEach { mapped ->
                if (isChainRelevantMappedFile(mapped, proc.processName)) {
                    addCandidate(mapped, "Chargé en mémoire par PID ${proc.pid} (${proc.processName})")
                }
            }
            proc.openFds.forEach { fdLine ->
                val target = fdLine.substringAfter("-> ", "").trim()
                if (target.startsWith("/vendor/") || target.startsWith("/system") || target.startsWith("/odm/") || target.startsWith("/product/")) {
                    addCandidate(target, "FD ouvert par PID ${proc.pid} (${proc.processName})")
                }
            }
        }

        // Découverte dynamique d'init.rc, permissions XML, manifestes VINTF & contextes SELinux liés aux acteurs vus
        onStatus("Recherche des scripts .rc, XML permissions, manifestes VINTF et overlays RRO liés à la chaîne...")
        val actorTokens = buildActorSearchTokens(input)
        val regexToken = actorTokens.take(18).joinToString("|") { Regex.escape(it) }
        val configScanCmd = """
            for root in /vendor/etc/init /system/etc/init /system_ext/etc/init /odm/etc/init /vendor/etc/vintf /system_ext/etc/vintf /vendor/etc/permissions /system/etc/permissions /system_ext/etc/permissions /product/etc/permissions /vendor/etc/selinux /system/etc/selinux /system_ext/etc/selinux; do
              if [ -d "${'$'}root" ]; then
                find "${'$'}root" -maxdepth 3 -type f 2>/dev/null | grep -iE '$regexToken|manifest|compatibility_matrix|file_contexts|hwservice_contexts|service_contexts' | head -n 40
              fi
            done
        """.trimIndent()
        shell.exec(configScanCmd, preferRoot = true, timeoutMs = 14_000L).stdout.lines().forEach { line ->
            val p = line.trim()
            if (p.startsWith("/")) addCandidate(p, "Configuration / Init / Manifest / SELinux lié à la chaîne")
        }

        // Overlays RRO & Packages actifs vus dans dumpsys overlay / dumpsys fingerprint / logcat
        val overlayDump = input.afterDumpsys["overlay"].orEmpty() + "\n" + input.beforeDumpsys["overlay"].orEmpty()
        val pkgNames = LinkedHashSet<String>()
        Regex("""\[x\]\s+([a-zA-Z0-9_.-]+)""").findAll(overlayDump).forEach { m ->
            val pkg = m.groupValues[1]
            val lower = pkg.lowercase()
            if (lower.contains("fp") || lower.contains("fod") || lower.contains("udfps") ||
                lower.contains("finger") || lower.contains("biometric") || lower.contains("systemui") ||
                lower.contains("display") || lower.contains("touch") || actorTokens.any { lower.contains(it) }
            ) {
                pkgNames.add(pkg)
            }
        }
        pkgNames.add("com.android.systemui")
        pkgNames.add("com.android.settings")

        input.timelineEvents.forEach { ev ->
            Regex("""(com\.[a-zA-Z0-9_.]+|vendor\.[a-zA-Z0-9_.]+)""").findAll(ev.summary + " " + ev.rawDetail).forEach { m ->
                val p = m.groupValues[1]
                if (p.length in 8..70 && !p.contains("..")) {
                    val pl = p.lowercase()
                    if (pl.contains("finger") || pl.contains("biometric") || pl.contains("udfps") ||
                        pl.contains("fod") || pl.contains("display") || pl.contains("touch")
                    ) {
                        pkgNames.add(p)
                    }
                }
            }
        }

        for (pkg in pkgNames.take(18)) {
            val pmPath = shell.exec("pm path ${RootShellExecutor.shellQuote(pkg)} 2>/dev/null", preferRoot = true, timeoutMs = 3_000L)
            pmPath.stdout.lines().forEach { line ->
                val apkPath = line.removePrefix("package:").trim()
                if (apkPath.startsWith("/")) {
                    addCandidate(apkPath, "Package actif / RRO / SystemUI observé ($pkg)")
                }
            }
        }

        // 3. Résolution récursive DT_NEEDED + extraction brute + reconstruction code source de CHAQUE fichier
        val extractedRecords = mutableListOf<LiveExtractedFileRecord>()
        val processed = LinkedHashSet<String>()
        val queue = ArrayDeque<Pair<String, String>>()
        candidatePaths.entries.take(140).forEach { (p, r) -> queue.add(p to r) }

        val dynamicKeywords = actorTokens.toSet()
        var idx = 0

        while (queue.isNotEmpty() && processed.size < 160) {
            val (path, reason) = queue.removeFirst()
            if (!processed.add(path)) continue
            if (BiometricPrivacyGuard.isProtectedBiometricPath(path)) continue

            idx++
            if (idx % 10 == 1) {
                onStatus("Extraction & code source ($idx/${queue.size + idx}) : ${path.substringAfterLast('/')}")
            }

            val sha = shell.computeSha256Safe(path, preferRoot = true)
            val cleanRel = path.trimStart('/')
            val extractedFile = File(rawDir, cleanRel)
            val copiedOk = if (path.endsWith(".apk") || path.endsWith(".jar")) {
                shell.copyFileToDestinationSafe(path, extractedFile, maxBytes = 40L * 1024L * 1024L)
            } else {
                shell.copyFileToDestinationSafe(path, extractedFile, maxBytes = 18L * 1024L * 1024L)
            }
            val sizeBytes = if (copiedOk) extractedFile.length() else 0L
            val extractedRel = if (copiedOk) "04_artefacts_extraits/$cleanRel" else null

            val category = classifyCategory(path)
            val kind = classifyKind(path)
            var rawPreview = ""
            var reconstructedSource = ""
            var sourceFileNameSuffix = ".txt"

            val bytes = if (copiedOk && extractedFile.length() <= 28_000_000L) {
                runCatching { extractedFile.readBytes() }.getOrNull()
            } else {
                shell.readFileBytesSafe(path, maxBytes = 20 * 1024 * 1024, preferRoot = true)
            }

            if (bytes != null && bytes.isNotEmpty()) {
                when {
                    path.endsWith(".so") || isElfMagic(bytes) -> {
                        val elf = ElfAnalyzer.analyze(
                            bytes = bytes,
                            availableLibraries = libIndex,
                            dynamicKeywords = dynamicKeywords,
                            sourcePath = path
                        )
                        if (elf != null) {
                            sourceFileNameSuffix = ".cpp"
                            val liveAnnotations = buildElfLiveAnnotations(path, input)
                            reconstructedSource = liveAnnotations + "\n" + elf.pseudoSourceCode
                            rawPreview = "ELF ${elf.machine} | SONAME=${elf.soName ?: "-"} | DT_NEEDED=${elf.neededLibraries.joinToString(", ")}"

                            // Enqueue transitive ELF dependencies if non-generic
                            elf.resolvedDependencies.values.forEach { depPath ->
                                if (!processed.contains(depPath) && !isGenericNoiseBinary(depPath)) {
                                    queue.add(depPath to "Dépendance DT_NEEDED de ${path.substringAfterLast('/')}")
                                }
                            }
                            // Check strings inside ELF pointing to config/sysfs/xml/.rc
                            elf.fodStrings.filter { s ->
                                s.startsWith("/vendor/") || s.startsWith("/sys/") || s.startsWith("/dev/") || s.endsWith(".rc") || s.endsWith(".xml")
                            }.take(10).forEach { ref ->
                                if (ref.startsWith("/vendor/") && !ref.contains("%s") && !processed.contains(ref)) {
                                    queue.add(ref to "Chemin référencé dans chaînes ELF de ${path.substringAfterLast('/')}")
                                }
                            }
                        }
                    }

                    path.endsWith(".apk") || path.endsWith(".jar") -> {
                        val dexRro = DexAndRroAnalyzer.analyzeApkOrJarBytes(
                            sourcePath = path,
                            zipBytes = bytes,
                            dynamicKeywords = dynamicKeywords
                        )
                        sourceFileNameSuffix = if (dexRro?.pseudoSourceCode?.isNotBlank() == true) ".java" else ".xml"
                        reconstructedSource = buildString {
                            appendLine("// Code source & Manifest reconstruit depuis : $path")
                            appendLine("// Raison d'inclusion dans la chaîne Live FOD : $reason")
                            if (dexRro != null) {
                                appendLine("// Package : ${dexRro.packageName ?: "?"} | RRO cible : ${dexRro.rroTargetPackage ?: "N/A"} (priorité=${dexRro.rroPriority ?: "-"})")
                                appendLine()
                                if (dexRro.decodedRroXml.isNotBlank()) {
                                    appendLine("/* ===== XML & RESOURCES DECODÉS ===== */")
                                    appendLine(dexRro.decodedRroXml)
                                    appendLine()
                                }
                                if (dexRro.pseudoSourceCode.isNotBlank()) {
                                    appendLine("/* ===== QUASI-CODE JAVA DEX FOD/UDFPS/DISPLAY/TOUCH ===== */")
                                    appendLine(dexRro.pseudoSourceCode)
                                }
                            } else {
                                appendLine("// Aucune classe DEX ou ressource UDFPS explicite extraite (archive ressources/système).")
                            }
                        }
                        rawPreview = reconstructedSource.take(2500)
                    }

                    else -> {
                        // Texte brut (.rc, .xml, .cil, .prop, file_contexts, etc.)
                        val text = String(bytes, Charsets.UTF_8)
                        rawPreview = text.take(4000)
                        val ext = path.substringAfterLast('.', "txt").lowercase()
                        sourceFileNameSuffix = if (ext in setOf("rc", "xml", "te", "cil", "prop", "conf", "sh")) ".$ext" else ".txt"
                        reconstructedSource = buildString {
                            appendLine("# Fichier source extrait : $path")
                            appendLine("# Rôle dans la chaîne Live FOD : $reason")
                            appendLine("# SHA-256 : $sha")
                            appendLine()
                            appendLine(text.take(90_000))
                        }
                    }
                }
            } else {
                reconstructedSource = "// Lecture directe indisponible ou accès restreint pour $path ($reason)"
            }

            var sourceRel: String? = null
            if (reconstructedSource.isNotBlank()) {
                val srcTarget = File(srcDir, "${cleanRel}$sourceFileNameSuffix")
                srcTarget.parentFile?.mkdirs()
                runCatching {
                    srcTarget.writeText(reconstructedSource)
                    sourceRel = "05_code_source_reconstruit/${cleanRel}$sourceFileNameSuffix"
                }
            }

            extractedRecords.add(
                LiveExtractedFileRecord(
                    id = "lf_${idx}",
                    category = category,
                    originalPath = path,
                    extractedRelPath = extractedRel,
                    sourceCodeRelPath = sourceRel,
                    sha256 = sha,
                    sizeBytes = sizeBytes,
                    kind = kind,
                    reasonInChain = reason,
                    rawPreview = rawPreview.take(3500),
                    reconstructedSourceCode = reconstructedSource.take(28_000)
                )
            )
        }

        // 4. Ajouter le code source reconstruit des nœuds DeviceTree & Sysfs modifiés
        val dtProbe = DeviceTreeAndSysfsProbe(shell)
        val dtNodes = runCatching { dtProbe.probeDeviceTree(dynamicKeywords) }.getOrDefault(emptyList())
        dtNodes.take(25).forEachIndexed { dtIdx, dt ->
            val rel = "devicetree/${dt.nodePath.trimStart('/')}.dtsi"
            val dst = File(srcDir, rel)
            dst.parentFile?.mkdirs()
            runCatching { dst.writeText(dt.pseudoDtsi) }
            extractedRecords.add(
                LiveExtractedFileRecord(
                    id = "dt_${dtIdx}",
                    category = "Device Tree",
                    originalPath = dt.nodePath,
                    extractedRelPath = null,
                    sourceCodeRelPath = "05_code_source_reconstruit/$rel",
                    sha256 = "N/A",
                    sizeBytes = dt.pseudoDtsi.length.toLong(),
                    kind = "Nœud Device Tree (.dtsi)",
                    reasonInChain = "Binding matériel détecté (${dt.compatible ?: "FDT"})",
                    rawPreview = dt.pseudoDtsi.take(2000),
                    reconstructedSourceCode = dt.pseudoDtsi
                )
            )
        }

        // 5. Synthétiser le mécanisme réel découvert (sans a priori)
        val mechanism = synthesizeDiscoveredMechanism(input, extractedRecords)

        // 6. Générer tous les patchs d'imitation basés sur la chaîne réelle observée
        val patches = synthesizeLivePatches(input, mechanism, extractedRecords)

        LiveExtractionOutput(
            extractedFiles = extractedRecords,
            mechanism = mechanism,
            patches = patches
        )
    }

    private fun buildElfLiveAnnotations(path: String, input: LiveExtractionInput): String {
        val sb = StringBuilder()
        sb.appendLine("// ===========================================================================")
        sb.appendLine("// ANALYSE LIVE FOD — CONTEXTE D'EXÉCUTION OBSERVÉ POUR : $path")
        sb.appendLine("// ===========================================================================")
        val users = input.halProcesses.filter { proc ->
            proc.mappedFiles.any { it == path } || proc.cmdline.contains(path.substringAfterLast('/'))
        }
        if (users.isNotEmpty()) {
            users.forEach { proc ->
                sb.appendLine("// Chargé par PID=${proc.pid} (${proc.processName}) | SELinux=${proc.seLinuxContext}")
                if (proc.openFds.isNotEmpty()) {
                    sb.appendLine("// FD ouverts pertinents : ${proc.openFds.take(8).joinToString(" | ")}")
                }
                if (proc.straceHighlights.isNotEmpty()) {
                    sb.appendLine("// Syscalls observés (strace) : ${proc.straceHighlights.take(6).joinToString(" ; ")}")
                }
            }
        }
        return sb.toString()
    }

    private fun synthesizeDiscoveredMechanism(
        input: LiveExtractionInput,
        files: List<LiveExtractedFileRecord>
    ): LiveDiscoveredMechanism {
        val hops = mutableListOf<LiveCallChainHop>()

        // Étape 1 : Interface Utilisateur Paramètres & SystemUI
        val uiEvents = input.timelineEvents.filter {
            val s = (it.actor + " " + it.summary + " " + it.rawDetail).lowercase()
            s.contains("systemui") || s.contains("udfps") || s.contains("enroll") || s.contains("biometricprompt") || s.contains("settings")
        }
        val uiPackages = files.filter { it.originalPath.endsWith(".apk") || it.originalPath.endsWith(".jar") }
            .map { it.originalPath }
        hops.add(
            LiveCallChainHop(
                order = 1,
                hopName = "Interface Paramètres / SystemUI / Overlays",
                layerTag = "Framework & UI",
                actorsObserved = uiEvents.map { it.actor }.distinct().take(8),
                filesAndNodesInvolved = uiPackages.take(8),
                outcome = when {
                    uiEvents.any { it.outcome == LiveOutcome.ERREUR_EXPLICITE } -> LiveOutcome.ERREUR_EXPLICITE
                    uiEvents.isNotEmpty() -> LiveOutcome.REACTION_DETECTEE
                    else -> LiveOutcome.SILENCE_RADIO
                },
                factualEvidence = if (uiEvents.isNotEmpty()) {
                    "${uiEvents.size} interaction(s) UI/SystemUI relevée(s). Dernière : ${uiEvents.last().summary}"
                } else {
                    "Aucun événement SystemUI/UDFPS intercepté pendant la fenêtre."
                }
            )
        )

        // Étape 2 : Tactile (getevent + touchfeature / input)
        val touchEvents = input.timelineEvents.filter { it.source == LiveEventSource.TOUCH_GETEVENT }
        val touchSysfs = input.sysfsTransitions.filter { it.category.contains("Tactile", true) || it.path.contains("touch", true) }
        hops.add(
            LiveCallChainHop(
                order = 2,
                hopName = "Acquisition Tactile & Capteur Doigt",
                layerTag = "Input / Touch",
                actorsObserved = touchEvents.map { it.actor }.distinct().take(6),
                filesAndNodesInvolved = touchSysfs.map { it.path }.take(8),
                outcome = when {
                    touchEvents.isNotEmpty() || touchSysfs.any { it.hasChanged } -> LiveOutcome.REACTION_DETECTEE
                    else -> LiveOutcome.SILENCE_RADIO
                },
                factualEvidence = "${touchEvents.size} trame(s) getevent capturée(s), ${touchSysfs.count { it.hasChanged }} transition(s) sysfs tactile."
            )
        )

        // Étape 3 : Affichage / Illumination (SurfaceFlinger, HBM, LHBM, DisplayFeature, PQ, sec_fp)
        val dispSysfsChanged = input.sysfsTransitions.filter {
            it.hasChanged && (it.category.contains("Affichage", true) || it.path.contains("hbm", true) ||
                it.path.contains("bright", true) || it.path.contains("drm", true) || it.path.contains("disp", true))
        }
        val sfDuring = input.duringDumpsys["SurfaceFlinger"].orEmpty() + "\n" + input.afterDumpsys["SurfaceFlinger"].orEmpty()
        val sfUdfpsLayers = sfDuring.lines().filter {
            val l = it.lowercase()
            l.contains("udfps") || l.contains("fod") || l.contains("fingerprint") || l.contains("hbm") || l.contains("dim")
        }.distinct().take(8)
        val dispDaemons = input.halProcesses.filter {
            val p = it.processName.lowercase()
            p.contains("display") || p.contains("composer") || p.contains("surfaceflinger") || p.contains("pq")
        }.map { "${it.processName} (PID ${it.pid})" }

        val dispMethod = buildString {
            if (sfUdfpsLayers.isNotEmpty()) append("Layers SurfaceFlinger détectés (${sfUdfpsLayers.size})")
            if (dispSysfsChanged.isNotEmpty()) {
                if (isNotEmpty()) append(" + ")
                append("Transitions sysfs (${dispSysfsChanged.joinToString(", ") { it.path.substringAfterLast('/') }})")
            }
            if (isEmpty()) append("Aucune illumination HBM/Overlay observée pendant l'enregistrement")
        }
        hops.add(
            LiveCallChainHop(
                order = 3,
                hopName = "Illumination Optique / Écran / Display HAL",
                layerTag = "Affichage & HBM",
                actorsObserved = dispDaemons,
                filesAndNodesInvolved = (dispSysfsChanged.map { it.path } + sfUdfpsLayers.map { it.trim().take(70) }).take(10),
                outcome = if (sfUdfpsLayers.isNotEmpty() || dispSysfsChanged.isNotEmpty()) LiveOutcome.REACTION_DETECTEE else LiveOutcome.SILENCE_RADIO,
                factualEvidence = dispMethod
            )
        )

        // Étape 4 : Daemons HAL / Binder / IPC
        val halDaemons = input.halProcesses.filter {
            val p = it.processName.lowercase()
            p.contains("finger") || p.contains("biometric") || p.contains("goodix") || p.contains("fpc") ||
                p.contains("silead") || p.contains("focal") || p.contains("egistec") || p.contains("tee") || p.contains("qsee")
        }
        val halEvents = input.timelineEvents.filter {
            it.source == LiveEventSource.HAL_PROC || it.source == LiveEventSource.BINDER_IPC ||
                (it.source == LiveEventSource.LOGCAT_FOD && (it.actor.lowercase().contains("hal") || it.actor.lowercase().contains("finger") || it.summary.lowercase().contains("goodix")))
        }
        hops.add(
            LiveCallChainHop(
                order = 4,
                hopName = "Daemons Biométriques HAL & Chaîne Binder/IPC",
                layerTag = "HAL & IPC",
                actorsObserved = halDaemons.map { "${it.processName} (PID ${it.pid})" },
                filesAndNodesInvolved = halDaemons.flatMap { it.mappedFiles.take(5) + it.openFds.take(5) }.distinct().take(12),
                outcome = when {
                    halEvents.any { it.outcome == LiveOutcome.ERREUR_EXPLICITE } -> LiveOutcome.ERREUR_EXPLICITE
                    halDaemons.isNotEmpty() && halEvents.isNotEmpty() -> LiveOutcome.REACTION_DETECTEE
                    halDaemons.isNotEmpty() -> LiveOutcome.TRANSITION_ETAT
                    else -> LiveOutcome.SILENCE_RADIO
                },
                factualEvidence = "${halDaemons.size} processus HAL actif(s), ${halEvents.size} événement(s) logcat/proc."
            )
        )

        // Étape 5 : Noyau, Syscalls /dev/*, dmesg, SELinux & Keystore/fpdata
        val kernelAndAvc = input.timelineEvents.filter {
            it.source == LiveEventSource.DMESG_KERNEL || it.source == LiveEventSource.SELINUX_AVC
        }
        val avcErrors = input.avcLines.distinct()
        hops.add(
            LiveCallChainHop(
                order = 5,
                hopName = "Noyau, Pilotes /dev/*, SELinux & Keystore/TEE",
                layerTag = "Kernel / SELinux / TEE",
                actorsObserved = input.halProcesses.filter {
                    val n = it.processName.lowercase()
                    n.contains("keystore") || n.contains("gatekeeper") || n.contains("tee")
                }.map { "${it.processName} (PID ${it.pid})" },
                filesAndNodesInvolved = (input.halProcesses.flatMap { it.openFds }.filter { it.contains("/dev/") }).distinct().take(10),
                outcome = when {
                    avcErrors.isNotEmpty() -> LiveOutcome.ERREUR_EXPLICITE
                    kernelAndAvc.isNotEmpty() -> LiveOutcome.REACTION_DETECTEE
                    else -> LiveOutcome.INFO_TECHNIQUE
                },
                factualEvidence = if (avcErrors.isNotEmpty()) {
                    "${avcErrors.size} refus SELinux avc: denied observé(s) durant l'essai."
                } else {
                    "${kernelAndAvc.size} message(s) noyau corrélés, 0 refus avc: denied détecté."
                }
            )
        )

        // Étape 6 : Résultat final d'enrôlement observé dans dumpsys / logcat
        val errorSignatures = input.timelineEvents
            .filter { it.outcome == LiveOutcome.ERREUR_EXPLICITE }
            .map { "${it.source.labelFr}: ${it.summary}" }
            .distinct()
            .take(15)

        val logBlob = input.timelineEvents.joinToString("\n") { "${it.summary} ${it.rawDetail}" }.lowercase()
        val fpDumpAfter = input.afterDumpsys["fingerprint"].orEmpty().lowercase()
        val enrollSucceeded = logBlob.contains("remaining=0") || logBlob.contains("enroll_result") && logBlob.contains("remaining: 0") ||
            logBlob.contains("enrolled") && !logBlob.contains("error") ||
            extractEnrolledCount(input.afterDumpsys["fingerprint"].orEmpty()) > extractEnrolledCount(input.beforeDumpsys["fingerprint"].orEmpty())

        val verdict = when {
            enrollSucceeded -> "SUCCÈS D'ENRÔLEMENT OBSERVÉ (nouvelle empreinte ou remaining=0 atteint)"
            errorSignatures.isNotEmpty() -> "ÉCHEC AVEC ERREUR EXPLICITE (${errorSignatures.size} signature(s) d'erreur)"
            uiEvents.isEmpty() && touchEvents.isEmpty() && dispSysfsChanged.isEmpty() -> "AUCUNE RÉACTION OBSERVÉE (chaîne silencieuse)"
            dispSysfsChanged.isEmpty() && sfUdfpsLayers.isEmpty() -> "BLOCAGE PARTIEL : pas d'illumination HBM/Overlay observée pendant le toucher"
            else -> "ENRÔLEMENT INCOMPLET OU ANNULÉ SANS ERREUR FATALE"
        }

        val archSummary = buildString {
            val halNames = halDaemons.map { it.processName.substringAfterLast('/') }.distinct()
            append(if (halNames.isNotEmpty()) halNames.joinToString(" + ") else "Aucun daemon HAL détecté")
            if (dispDaemons.isNotEmpty()) append(" ↔ Display(${dispDaemons.first().substringBefore(" ")})")
            if (dispSysfsChanged.isNotEmpty()) append(" → Sysfs(${dispSysfsChanged.first().path.substringAfterLast('/')})")
        }

        val explanation = buildString {
            appendLine("Mécanisme réel observé : $archSummary.")
            appendLine("Verdict factuel de la tentative : $verdict.")
            appendLine("Fichiers réellement impliqués extraits : ${files.size} (${files.count { it.sourceCodeRelPath != null }} avec code source reconstruit).")
            if (errorSignatures.isNotEmpty()) {
                appendLine("Erreurs capturées : ${errorSignatures.take(5).joinToString(" | ")}")
            }
        }.trim()

        return LiveDiscoveredMechanism(
            primaryArchitecture = archSummary,
            enrollmentVerdict = verdict,
            explanationFr = explanation,
            displayIlluminationMethod = dispMethod,
            touchInteractionMethod = if (touchEvents.isNotEmpty()) "${touchEvents.size} événements getevent + ${touchSysfs.size} nœuds sysfs" else "Aucun événement tactile brut capturé",
            binderAndHalDaemons = (halDaemons.map { it.processName } + dispDaemons).distinct(),
            activePackagesInChain = uiPackages.map { it.substringAfterLast('/') }.distinct(),
            errorSignatures = errorSignatures,
            hops = hops
        )
    }

    private fun extractEnrolledCount(fpDump: String): Int {
        val m = Regex("""enrolled\s*[:=]\s*(\d+)""", RegexOption.IGNORE_CASE).find(fpDump)
        if (m != null) return m.groupValues[1].toIntOrNull() ?: 0
        return Regex("""fingerid|biometricId""", RegexOption.IGNORE_CASE).findAll(fpDump).count()
    }

    private fun synthesizeLivePatches(
        input: LiveExtractionInput,
        mechanism: LiveDiscoveredMechanism,
        files: List<LiveExtractedFileRecord>
    ): List<LiveGeneratedPatch> {
        val patches = mutableListOf<LiveGeneratedPatch>()

        // 1. SELinux Live Policy
        val seRules = LinkedHashSet<String>()
        input.avcLines.forEach { raw ->
            val sc = Regex("""scontext=u:r:([^:\s]+)""").find(raw)?.groupValues?.getOrNull(1)
            val tc = Regex("""tcontext=u:object_r:([^:\s]+)""").find(raw)?.groupValues?.getOrNull(1)
            val cl = Regex("""tclass=([^\s]+)""").find(raw)?.groupValues?.getOrNull(1)
            val perm = Regex("""\{\s*([^}]+)\s*\}""").find(raw)?.groupValues?.getOrNull(1)?.trim()
            if (sc != null && tc != null && cl != null && perm != null) {
                seRules.add("allow $sc $tc:$cl { $perm };")
            }
        }
        val sePatch = buildString {
            appendLine("# Patch SELinux généré depuis les refus réels observés pendant Live FOD")
            if (seRules.isEmpty()) {
                appendLine("# Aucun refus avc: denied détecté pendant cette session.")
            } else {
                seRules.forEach { appendLine(it) }
            }
            appendLine()
            appendLine("# Contextes observés sur les processus de la chaîne :")
            input.halProcesses.forEach { p ->
                appendLine("# PID ${p.pid} (${p.processName}) -> ${p.seLinuxContext}")
            }
        }
        patches.add(
            LiveGeneratedPatch(
                id = "live_patch_se",
                fileName = "patch_selinux_live.te",
                title = "Règles SELinux réelles observées (.te)",
                kind = "SELinux Policy",
                targetPathHint = "magiskpolicy --live / vendor sepolicy",
                description = "${seRules.size} règle(s) extraite(s) des refus avc: denied pendant l'essai d'enrôlement.",
                codeContent = sePatch
            )
        )

        // 2. Init.rc & sysfs permissions
        val touchedSysfsAndDev = (
            input.sysfsTransitions.map { it.path to "${it.permissions} ${it.seLinuxContext}" } +
                input.halProcesses.flatMap { p ->
                    p.openFds.map { it.substringAfter("-> ", "").trim() }
                        .filter { it.startsWith("/dev/") || it.startsWith("/sys/") }
                        .map { it to "Ouvert par ${p.processName} (${p.uid})" }
                }
            ).distinctBy { it.first }

        val rcContent = buildString {
            appendLine("# Patch Init & Nœuds Sysfs/Dev réellement sollicités pendant Live FOD")
            appendLine("on post-fs-data")
            touchedSysfsAndDev.take(40).forEach { (node, meta) ->
                appendLine("    # $meta")
                appendLine("    chmod 0664 $node")
                appendLine("    chown system system $node")
            }
        }
        patches.add(
            LiveGeneratedPatch(
                id = "live_patch_rc",
                fileName = "patch_init_et_sysfs_live.rc",
                title = "Permissions Nœuds /sys & /dev de la chaîne (.rc)",
                kind = "Init & Sysfs",
                targetPathHint = "/vendor/etc/init/ ou service.sh Magisk",
                description = "Aligne l'accès aux ${touchedSysfsAndDev.size} nœuds /sys et /dev réellement utilisés lors du scan.",
                codeContent = rcContent
            )
        )

        // 3. Propriétés FOD / Display / Tactile actives
        val activeProps = input.afterProps.filter { (k, _) ->
            val kl = k.lowercase()
            kl.contains("finger") || kl.contains("fod") || kl.contains("udfps") ||
                kl.contains("hbm") || kl.contains("lhbm") || kl.contains("biometric") ||
                kl.contains("touch") || kl.contains("display")
        }
        val propContent = buildString {
            appendLine("# Propriétés système actives pendant la capture Live FOD")
            activeProps.toSortedMap().forEach { (k, v) ->
                appendLine("$k=$v")
            }
        }
        patches.add(
            LiveGeneratedPatch(
                id = "live_patch_prop",
                fileName = "patch_proprietes_live.prop",
                title = "Propriétés système observées (system.prop)",
                kind = "Propriétés",
                targetPathHint = "module_magisk/system.prop",
                description = "${activeProps.size} propriété(s) biométriques/affichage/tactiles capturées durant l'exécution.",
                codeContent = propContent
            )
        )

        // 4. Blueprint complet de la chaîne & des fichiers à reproduire
        val chainContent = buildString {
            appendLine("# Blueprint d'imitation du mécanisme observé : ${mechanism.primaryArchitecture}")
            appendLine("# Verdict : ${mechanism.enrollmentVerdict}")
            appendLine()
            appendLine("## Daemons & Interfaces IPC actifs :")
            mechanism.binderAndHalDaemons.forEach { appendLine("- $it") }
            appendLine()
            appendLine("## Chaque fichier entré dans la chaîne d'interaction (${files.size}) :")
            files.forEach { f ->
                appendLine("- [${f.category}] ${f.originalPath} | sha256=${f.sha256.take(16)} | source=${f.sourceCodeRelPath ?: "non"} | raison=${f.reasonInChain}")
            }
        }
        patches.add(
            LiveGeneratedPatch(
                id = "live_patch_blueprint",
                fileName = "patch_mecanisme_et_libs_live.md",
                title = "Blueprint mécanisme & liste intégrale des fichiers appelés",
                kind = "Architecture & Fichiers",
                targetPathHint = "04_artefacts_extraits/ & 05_code_source_reconstruit/",
                description = "Documente tous les acteurs IPC et chaque fichier (.so, .apk, .rc, .xml, sysfs) impliqué dans la chaîne.",
                codeContent = chainContent
            )
        )

        return patches
    }

    private fun buildActorSearchTokens(input: LiveExtractionInput): List<String> {
        val tokens = LinkedHashSet<String>()
        tokens.addAll(listOf("fingerprint", "biometric", "udfps", "fod", "goodix", "fpc", "silead", "focal", "egistec", "displayfeature", "touchfeature", "hbm", "lhbm", "keystore", "gatekeeper"))
        input.halProcesses.forEach { proc ->
            val short = proc.processName.substringAfterLast('/').lowercase()
            short.split('.', '-', '_', '@').filter { it.length >= 4 && it != "vendor" && it != "android" && it != "hardware" && it != "service" }.forEach {
                tokens.add(it)
            }
        }
        return tokens.toList()
    }

    private fun isChainRelevantMappedFile(path: String, processName: String): Boolean {
        if (isGenericNoiseBinary(path)) return false
        val pl = processName.lowercase()
        val pathL = path.lowercase()
        // Pour les démons HAL/vendor biométriques ou display, garder TOUS leurs .so/.apk/.jar non-libc standard
        if (pl.contains("finger") || pl.contains("biometric") || pl.contains("goodix") ||
            pl.contains("fpc") || pl.contains("silead") || pl.contains("display") || pl.contains("touch")
        ) {
            return pathL.startsWith("/vendor/") || pathL.startsWith("/odm/") ||
                pathL.startsWith("/system_ext/") || pathL.startsWith("/product/") ||
                pathL.contains("finger") || pathL.contains("bio") || pathL.contains("hbm") ||
                pathL.contains("display") || pathL.contains("touch") || pathL.contains("tee") || pathL.contains("qsee")
        }
        // Pour system_server / SystemUI / surfaceflinger, filtrer aux composants pertinents pour éviter 400 libs système
        return pathL.contains("finger") || pathL.contains("biometric") || pathL.contains("udfps") ||
            pathL.contains("fod") || pathL.contains("systemui") || pathL.contains("overlay") ||
            pathL.contains("display") || pathL.contains("touch") || pathL.contains("hbm") ||
            pathL.contains("goodix") || pathL.contains("keystore") || pathL.startsWith("/vendor/")
    }

    private fun isGenericNoiseBinary(path: String): Boolean {
        val name = path.substringAfterLast('/')
        return name in setOf(
            "libc.so", "libm.so", "libdl.so", "libz.so", "liblog.so",
            "libc++.so", "libcutils.so", "libutils.so", "libbase.so",
            "libbinder.so", "libbinder_ndk.so", "libhidlbase.so", "libstdc++.so"
        ) || path.endsWith(".art") || path.endsWith(".oat") || path.endsWith(".vdex") || path.endsWith(".odex")
    }

    private fun isElfMagic(bytes: ByteArray): Boolean {
        return bytes.size >= 4 &&
            bytes[0] == 0x7F.toByte() &&
            bytes[1] == 'E'.code.toByte() &&
            bytes[2] == 'L'.code.toByte() &&
            bytes[3] == 'F'.code.toByte()
    }

    private fun classifyCategory(path: String): String = when {
        path.endsWith(".so") -> "Bibliothèques ELF (.so)"
        path.endsWith(".apk") || path.endsWith(".jar") -> "APK / RRO / Framework"
        path.endsWith(".rc") -> "Scripts Init (.rc)"
        path.endsWith(".xml") -> "Manifestes & Permissions XML"
        path.contains("selinux") || path.endsWith(".cil") || path.endsWith("_contexts") -> "SELinux"
        else -> "Binaires & Configs Chaîne"
    }

    private fun classifyKind(path: String): String = when {
        path.endsWith(".so") -> "Bibliothèque native (.so)"
        path.endsWith(".apk") -> "Package / Overlay APK"
        path.endsWith(".jar") -> "Archive Java/DEX (.jar)"
        path.endsWith(".rc") -> "Script Init Android (.rc)"
        path.endsWith(".xml") -> "Descripteur XML / VINTF / Permission"
        else -> "Artefact système"
    }
}

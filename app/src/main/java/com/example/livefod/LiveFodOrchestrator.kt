package com.example.livefod

import android.os.Build
import com.example.core.BiometricPrivacyGuard
import com.example.core.RootShellExecutor
import com.example.model.RomEnvironmentType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class LiveFodOrchestrator(
    private val shell: RootShellExecutor,
    private val storage: LiveFodStorageManager
) {
    private val extractor = LiveFodArtifactExtractor(shell)

    suspend fun runSession(
        sessionLabel: String,
        stopSignal: AtomicBoolean,
        touchMarkerCount: AtomicInteger,
        onHudUpdate: ((LiveCaptureHudState) -> LiveCaptureHudState) -> Unit
    ): LiveFodSession = withContext(Dispatchers.IO) {
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).format(Date())
        val safeSuffix = sessionLabel.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(22).ifBlank { "SESSION" }
        val sessionId = "LIVE_${safeSuffix}_$stamp"
        val sessionDir = storage.prepareNewSessionWorkingDir(sessionId)
        val rawLogsDir = File(sessionDir, "02_logs_bruts").apply { mkdirs() }
        val dumpsDir = File(sessionDir, "03_dumpsys_et_ipc").apply { mkdirs() }

        val startMs = System.currentTimeMillis()
        fun relTime(now: Long = System.currentTimeMillis()): String {
            val diff = maxOf(0L, now - startMs)
            val sec = diff / 1000
            val ms = diff % 1000
            return String.format(Locale.US, "+%02d.%03ds", sec, ms)
        }

        val timelineEvents = Collections.synchronizedList(mutableListOf<LiveInteractionEvent>())
        val discoveredPaths = Collections.synchronizedMap(LinkedHashMap<String, String>())
        val avcLines = Collections.synchronizedList(mutableListOf<String>())
        val recentLogs = Collections.synchronizedList(mutableListOf<String>())
        val halSnapshotsMap = Collections.synchronizedMap(LinkedHashMap<String, LiveHalProcessSnapshot>())
        val dmesgAllLines = Collections.synchronizedList(mutableListOf<String>())

        val rawLogcatCount = AtomicInteger(0)
        val filteredFodCount = AtomicInteger(0)
        val dmesgCount = AtomicInteger(0)
        val touchCount = AtomicInteger(0)
        val sysfsTransCount = AtomicInteger(0)
        val halSnapCount = AtomicInteger(0)
        var lastMarkerSeen = 0

        fun addTimelineEvent(
            source: LiveEventSource,
            actor: String,
            outcome: LiveOutcome,
            summary: String,
            rawDetail: String
        ) {
            val now = System.currentTimeMillis()
            val rel = relTime(now)
            if (timelineEvents.size < 2500) {
                timelineEvents.add(
                    LiveInteractionEvent(
                        id = "ev_${timelineEvents.size}_${now % 10000}",
                        timestampMs = now,
                        relativeTimeLabel = rel,
                        source = source,
                        actor = actor,
                        outcome = outcome,
                        summary = summary.take(260),
                        rawDetail = rawDetail.take(1000)
                    )
                )
            }
            synchronized(recentLogs) {
                recentLogs.add("[$rel] [${source.labelFr}] $actor : ${summary.take(110)}")
                if (recentLogs.size > 40) recentLogs.removeAt(0)
            }
            onHudUpdate { cur ->
                cur.copy(
                    lastLiveHeadline = "[$rel] $summary".take(120),
                    recentLiveLogs = synchronized(recentLogs) { recentLogs.toList() }
                )
            }
        }

        onHudUpdate {
            LiveCaptureHudState(
                phase = LiveCapturePhase.CAPTURING_PRE,
                sessionId = sessionId,
                sessionLabel = sessionLabel.ifBlank { sessionId }
            )
        }

        // ── PHASE AVANT (T0) ───────────────────────────────────────────────────────
        val rootInfo = shell.detectRoot(forceRecheck = true)
        val getpropBeforeRaw = shell.exec("getprop", preferRoot = true, timeoutMs = 10_000L).stdout
        File(dumpsDir, "getprop_avant.txt").writeText(getpropBeforeRaw)
        val beforeProps = parseProps(getpropBeforeRaw)

        val isDsuActive = beforeProps.any { (k, v) ->
            (k.contains("gsid") || k.contains("dsu") || k.contains("treble")) &&
                (v == "1" || v.equals("true", true) || v.contains("gsi", true))
        } || (beforeProps["ro.product.system.name"]?.contains("gsi", true) == true) ||
            (beforeProps["ro.build.flavor"]?.contains("gsi", true) == true)
        val romType = if (isDsuActive) RomEnvironmentType.GSI_DSU else RomEnvironmentType.ROM_ORIGINE

        val psBefore = shell.exec("ps -efZ 2>/dev/null || ps -A -Z 2>/dev/null", preferRoot = true, timeoutMs = 8_000L).stdout
        File(dumpsDir, "ps_avant.txt").writeText(psBefore)

        val lshalBefore = if (rootInfo.isGranted) {
            shell.exec("lshal --neat -i -t 2>/dev/null; echo '---SERVICE_LIST---'; service list 2>/dev/null", preferRoot = true, timeoutMs = 10_000L).stdout
        } else {
            "Mode non-root : lshal restreint"
        }
        File(dumpsDir, "avant_lshal_et_services.txt").writeText(lshalBefore)

        val beforeDumpsys = captureKeyDumpsys(rootInfo.isGranted)
        beforeDumpsys.forEach { (k, v) ->
            File(dumpsDir, "avant_dumpsys_${k}.txt").writeText(v)
        }

        val protectedBefore = auditProtectedMetadataSafe(rootInfo.isGranted)
        File(dumpsDir, "avant_zones_protegees.txt").writeText(protectedBefore)

        // Balayage Sysfs universel (T0) — découvre les nœuds affichage/DRM/backlight/tactile/platform sans a priori
        val sysfsNodesToWatch = discoverUniversalSysfsNodes(rootInfo.isGranted)
        val sysfsHistory = LinkedHashMap<String, MutableList<String>>()
        val sysfsInitialMap = readSysfsBatch(sysfsNodesToWatch, rootInfo.isGranted)
        sysfsInitialMap.forEach { (p, v) -> sysfsHistory[p] = mutableListOf(v) }
        File(dumpsDir, "sysfs_avant.txt").writeText(
            sysfsInitialMap.entries.joinToString("\n") { "${it.key} = ${it.value}" }
        )

        val dmesgSeed = if (rootInfo.isGranted) {
            shell.exec("dmesg 2>/dev/null | tail -n 120", preferRoot = true, timeoutMs = 6_000L).stdout
        } else ""
        val seenDmesgLines = Collections.synchronizedSet(dmesgSeed.lines().toHashSet())

        // ── PHASE CAPTURE LIVE (4 SONDES PARALLÈLES) ───────────────────────────────
        onHudUpdate {
            it.copy(
                phase = LiveCapturePhase.RECORDING_LIVE,
                lastLiveHeadline = "Sondes actives — allez dans Paramètres > Empreintes"
            )
        }
        addTimelineEvent(
            LiveEventSource.DUMPSYS_STATE,
            "LiveFOD",
            LiveOutcome.INFO_TECHNIQUE,
            "Capture T0 terminée (${sysfsNodesToWatch.size} nœuds sysfs surveillés, ${beforeDumpsys.size} dumpsys)",
            "Root: ${rootInfo.provider}"
        )

        val logcatRawFile = File(rawLogsDir, "logcat_complet_brut.txt")
        val logcatFilteredFile = File(rawLogsDir, "logcat_fod_filtre.txt")
        val dmesgFile = File(rawLogsDir, "dmesg_noyau_brut.txt")
        val geteventFile = File(rawLogsDir, "getevent_tactile_brut.txt")
        val sysfsTransFile = File(rawLogsDir, "sysfs_transitions_brutes.txt")
        val straceFile = File(rawLogsDir, "strace_hal_brut.txt")

        File(rawLogsDir, "getevent_devices.txt").writeText(
            shell.exec("getevent -pl 2>/dev/null", preferRoot = rootInfo.isGranted, timeoutMs = 5_000L).stdout
        )

        val liveDuringDumpsys = Collections.synchronizedMap(LinkedHashMap<String, String>())
        val jobs = mutableListOf<Job>()
        val activeProcesses = Collections.synchronizedList(mutableListOf<Process>())
        val activeChainPids = Collections.synchronizedSet(LinkedHashSet<String>())

        // Initialiser les PIDs candidats depuis psBefore
        collectCandidatePidsFromPs(psBefore).forEach { (pid, _) -> activeChainPids.add(pid) }

        val probeScope = CoroutineScope(Dispatchers.IO)

        // Sonde 1A : Stream Logcat complet + filtrage temps réel intelligent
        jobs += probeScope.launch {
            val nowStamp = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).format(Date(startMs - 500L))
            val proc = shell.startStreamingProcess("logcat -v threadtime -b all -T '$nowStamp'", preferRoot = rootInfo.isGranted)
            if (proc != null) {
                activeProcesses.add(proc)
                BufferedWriter(FileWriter(logcatRawFile, true)).use { rawW ->
                    BufferedWriter(FileWriter(logcatFilteredFile, true)).use { filtW ->
                        runCatching {
                            proc.inputStream.bufferedReader().use { reader ->
                                while (!stopSignal.get() && isActive) {
                                    val line = reader.readLine() ?: break
                                    rawW.write(line)
                                    rawW.newLine()
                                    val cRaw = rawLogcatCount.incrementAndGet()
                                    if (cRaw % 50 == 0) {
                                        rawW.flush()
                                        onHudUpdate { it.copy(logcatRawLines = cRaw) }
                                    }

                                    if (isRelevantLiveLogcatLine(line, activeChainPids)) {
                                        filtW.write(line)
                                        filtW.newLine()
                                        filtW.flush()
                                        val cf = filteredFodCount.incrementAndGet()
                                        onHudUpdate { it.copy(filteredFodEvents = cf, logcatRawLines = cRaw) }

                                        // Extraire PID/chemins/avc dynamiquement depuis la ligne logcat
                                        extractPidFromThreadtime(line)?.let { pid ->
                                            if (line.lowercase().let { it.contains("finger") || it.contains("udfps") || it.contains("biometric") || it.contains("goodix") || it.contains("fod") }) {
                                                activeChainPids.add(pid)
                                            }
                                        }
                                        extractFilePathsFromText(line).forEach { path ->
                                            discoveredPaths.putIfAbsent(path, "Référencé en direct dans logcat")
                                        }
                                        if (line.contains("avc: denied", ignoreCase = true)) {
                                            avcLines.add(line)
                                            addTimelineEvent(
                                                LiveEventSource.SELINUX_AVC,
                                                extractTagFromThreadtime(line),
                                                LiveOutcome.ERREUR_EXPLICITE,
                                                "Refus SELinux AVC : ${line.substringAfter("avc: denied").take(140)}",
                                                line
                                            )
                                        } else {
                                            val outcome = classifyLogcatLineOutcome(line)
                                            addTimelineEvent(
                                                LiveEventSource.LOGCAT_FOD,
                                                extractTagFromThreadtime(line),
                                                outcome,
                                                line.substringAfter(": ").take(170),
                                                line
                                            )
                                        }
                                    }
                                }
                            }
                        }
                        runCatching { rawW.flush(); filtW.flush() }
                    }
                }
            }
        }

        // Sonde 1B : Polling dmesg noyau
        if (rootInfo.isGranted) {
            jobs += probeScope.launch {
                BufferedWriter(FileWriter(dmesgFile, true)).use { dmesgW ->
                    while (!stopSignal.get() && isActive) {
                        val out = shell.exec("dmesg 2>/dev/null | tail -n 160", preferRoot = true, timeoutMs = 4_000L).stdout
                        out.lines().forEach { line ->
                            if (line.isNotBlank() && seenDmesgLines.add(line)) {
                                dmesgW.write("[${relTime()}] $line")
                                dmesgW.newLine()
                                dmesgAllLines.add(line)
                                val dc = dmesgCount.incrementAndGet()
                                onHudUpdate { it.copy(dmesgEvents = dc) }
                                if (line.contains("avc: denied", ignoreCase = true)) {
                                    avcLines.add(line)
                                    addTimelineEvent(LiveEventSource.SELINUX_AVC, "kernel", LiveOutcome.ERREUR_EXPLICITE, line.take(160), line)
                                } else if (isInterestingKernelLine(line)) {
                                    extractFilePathsFromText(line).forEach { p ->
                                        discoveredPaths.putIfAbsent(p, "Référencé dans dmesg noyau")
                                    }
                                    addTimelineEvent(LiveEventSource.DMESG_KERNEL, "kernel", classifyKernelOutcome(line), line.take(160), line)
                                }
                            }
                        }
                        dmesgW.flush()
                        delay(800L)
                    }
                }
            }
        }

        // Sonde 2A : Stream tactile getevent -lt
        if (rootInfo.isGranted) {
            jobs += probeScope.launch {
                val proc = shell.startStreamingProcess("getevent -lt", preferRoot = true)
                if (proc != null) {
                    activeProcesses.add(proc)
                    BufferedWriter(FileWriter(geteventFile, true)).use { geW ->
                        var burstStartMs = 0L
                        var burstCount = 0
                        var lastEventDevice = ""
                        runCatching {
                            proc.inputStream.bufferedReader().use { reader ->
                                while (!stopSignal.get() && isActive) {
                                    val line = reader.readLine() ?: break
                                    geW.write(line)
                                    geW.newLine()
                                    val tc = touchCount.incrementAndGet()
                                    if (tc % 25 == 0) {
                                        geW.flush()
                                        onHudUpdate { it.copy(touchEvents = tc) }
                                    }

                                    val lower = line.lowercase()
                                    val devMatch = Regex("""(/dev/input/event\d+)""").find(line)?.groupValues?.getOrNull(1)
                                    if (devMatch != null) lastEventDevice = devMatch

                                    if (lower.contains("btn_touch") || lower.contains("key_fingerprint") || lower.contains("abs_mt_tracking_id")) {
                                        val now = System.currentTimeMillis()
                                        if (now - burstStartMs > 700L) {
                                            burstStartMs = now
                                            burstCount++
                                            addTimelineEvent(
                                                LiveEventSource.TOUCH_GETEVENT,
                                                lastEventDevice.ifBlank { "/dev/input" },
                                                LiveOutcome.REACTION_DETECTEE,
                                                "Interaction tactile/capteur #$burstCount : ${line.substringAfter("]").trim()}",
                                                line
                                            )
                                        }
                                    }
                                }
                            }
                        }
                        runCatching { geW.flush() }
                    }
                }
            }
        }

        // Sonde 2B : Polling haute fréquence Sysfs HBM / Display / Touch / FOD
        jobs += probeScope.launch {
            BufferedWriter(FileWriter(sysfsTransFile, true)).use { sysW ->
                while (!stopSignal.get() && isActive) {
                    val currentMap = readSysfsBatch(sysfsNodesToWatch, rootInfo.isGranted)
                    currentMap.forEach { (path, value) ->
                        val hist = sysfsHistory.getOrPut(path) { mutableListOf() }
                        if (hist.lastOrNull() != value) {
                            hist.add(value)
                            val line = "[${relTime()}] $path : '${hist.getOrNull(hist.size - 2) ?: "?"}' -> '$value'"
                            sysW.write(line)
                            sysW.newLine()
                            sysW.flush()
                            val sc = sysfsTransCount.incrementAndGet()
                            onHudUpdate { it.copy(sysfsTransitions = sc) }
                            addTimelineEvent(
                                LiveEventSource.SYSFS_POLL,
                                path.substringAfterLast('/'),
                                LiveOutcome.TRANSITION_ETAT,
                                "Sysfs modifié : $path -> $value",
                                line
                            )
                        }
                    }
                    delay(350L)
                }
            }
        }

        // Sonde 3 & 4 : Horloge HUD + Snapshots /proc/{maps,fd,status} + dumpsys PENDANT + strace + marqueurs
        jobs += probeScope.launch {
            var loopTick = 0
            var straceExecuted = false
            while (!stopSignal.get() && isActive) {
                val elapsed = (System.currentTimeMillis() - startMs) / 1000L
                val curMarkers = touchMarkerCount.get()
                if (curMarkers > lastMarkerSeen) {
                    lastMarkerSeen = curMarkers
                    addTimelineEvent(
                        LiveEventSource.USER_MARKER,
                        "Utilisateur",
                        LiveOutcome.INFO_TECHNIQUE,
                        "Marqueur toucher #$curMarkers posé — capture immédiate SurfaceFlinger & HAL",
                        "Repère manuel pour corrélation avec les sondes"
                    )
                    val sfNow = shell.exec("dumpsys SurfaceFlinger 2>/dev/null | head -n 220", preferRoot = rootInfo.isGranted, timeoutMs = 5_000L).stdout
                    liveDuringDumpsys["SurfaceFlinger"] = sfNow
                    File(dumpsDir, "pendant_marker_${curMarkers}_SurfaceFlinger.txt").writeText(sfNow)
                }

                // Inspection /proc des processus de la chaîne toutes les ~2.5s
                if (rootInfo.isGranted && loopTick % 5 == 0) {
                    val psNow = shell.exec("ps -efZ 2>/dev/null || ps -A -Z 2>/dev/null", preferRoot = true, timeoutMs = 4_000L).stdout
                    val pidMap = collectCandidatePidsFromPs(psNow)
                    activeChainPids.forEach { pid ->
                        if (!pidMap.containsKey(pid)) {
                            val cmd = shell.exec("tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null", preferRoot = true, timeoutMs = 1_500L).stdout.trim()
                            if (cmd.isNotBlank()) pidMap[pid] = cmd.substringBefore(" ")
                        }
                    }

                    pidMap.entries.take(12).forEach { (pid, name) ->
                        val procSnap = inspectProcessProcDeep(pid, name)
                        halSnapshotsMap[pid] = procSnap
                        procSnap.openFds.forEach { fdLine ->
                            val target = fdLine.substringAfter("-> ", "").trim()
                            if (target.startsWith("/sys/") && target !in sysfsNodesToWatch && sysfsNodesToWatch.size < 220) {
                                sysfsNodesToWatch.add(target)
                            }
                            if (target.startsWith("/")) {
                                discoveredPaths.putIfAbsent(target, "FD ouvert par $name (PID $pid)")
                            }
                        }
                    }
                    val hc = halSnapCount.incrementAndGet()
                    onHudUpdate { it.copy(halProcSnapshots = hc) }

                    // Exécuter un bref strace en lecture seule (3s max) une fois sur le daemon fingerprint principal si présent
                    if (!straceExecuted) {
                        straceExecuted = true
                        val fpPid = pidMap.entries.firstOrNull { (_, n) ->
                            val nl = n.lowercase()
                            nl.contains("finger") || nl.contains("goodix") || nl.contains("biometric")
                        }?.key
                        if (fpPid != null) {
                            val hasStrace = shell.exec("which strace 2>/dev/null || ls /system/bin/strace /system/xbin/strace 2>/dev/null", preferRoot = true, timeoutMs = 2_000L).stdout.trim()
                            if (hasStrace.isNotBlank()) {
                                val stOut = shell.exec(
                                    "timeout 3 strace -f -p $fpPid -e trace=ioctl,openat,connect 2>&1 | head -n 350",
                                    preferRoot = true,
                                    timeoutMs = 5_500L
                                ).stdout
                                File(rawLogsDir, "strace_hal_brut.txt").writeText(stOut)
                                val highlights = stOut.lines().filter {
                                    it.contains("ioctl(") || it.contains("openat(") || it.contains("EACCES") || it.contains("ENOENT") || it.contains("ENOTTY")
                                }.take(25)
                                halSnapshotsMap[fpPid]?.let { old ->
                                    halSnapshotsMap[fpPid] = old.copy(straceHighlights = highlights)
                                }
                                extractFilePathsFromText(stOut).forEach { p ->
                                    discoveredPaths.putIfAbsent(p, "Appelé via strace sur PID $fpPid")
                                }
                                if (highlights.isNotEmpty()) {
                                    addTimelineEvent(
                                        LiveEventSource.HAL_PROC,
                                        "strace(PID $fpPid)",
                                        if (highlights.any { it.contains("EACCES") || it.contains("ENOENT") }) LiveOutcome.ERREUR_EXPLICITE else LiveOutcome.INFO_TECHNIQUE,
                                        "Syscalls HAL capturés : ${highlights.size} entrées",
                                        highlights.take(8).joinToString("\n")
                                    )
                                }
                            } else {
                                straceFile.writeText("# strace non installé sur l'image Android (lecture /proc maps/fd/binder active).\n")
                            }
                        }
                    }
                }

                // Captures pendant dumpsys SurfaceFlinger / fingerprint toutes les ~5s
                if (loopTick % 10 == 4) {
                    val sf = shell.exec("dumpsys SurfaceFlinger 2>/dev/null | head -n 220", preferRoot = rootInfo.isGranted, timeoutMs = 4_000L).stdout
                    val fp = shell.exec("dumpsys fingerprint 2>/dev/null", preferRoot = rootInfo.isGranted, timeoutMs = 4_000L).stdout
                    liveDuringDumpsys["SurfaceFlinger"] = sf
                    liveDuringDumpsys["fingerprint"] = fp
                    File(dumpsDir, "pendant_dumpsys_SurfaceFlinger.txt").writeText(sf)
                    File(dumpsDir, "pendant_dumpsys_fingerprint.txt").writeText(fp)
                }

                onHudUpdate {
                    it.copy(
                        elapsedSeconds = elapsed,
                        touchMarkersCount = curMarkers,
                        logcatRawLines = rawLogcatCount.get(),
                        filteredFodEvents = filteredFodCount.get(),
                        dmesgEvents = dmesgCount.get(),
                        touchEvents = touchCount.get(),
                        sysfsTransitions = sysfsTransCount.get(),
                        halProcSnapshots = halSnapCount.get()
                    )
                }
                loopTick++
                delay(500L)
            }
        }

        // Attendre l'arrêt demandé par l'utilisateur
        while (!stopSignal.get()) {
            delay(250L)
        }

        // ── ARRÊT PROPRE DES PROCESSUS STREAMING ─────────────────────────────────
        onHudUpdate {
            it.copy(
                phase = LiveCapturePhase.CAPTURING_POST_AND_EXTRACTING,
                lastLiveHeadline = "Arrêt des sondes : capture APRÈS & extraction complète..."
            )
        }
        activeProcesses.forEach { p -> runCatching { p.destroyForcibly() } }
        jobs.forEach { j -> runCatching { j.cancel() } }
        delay(250L)

        // ── PHASE APRÈS (T_fin) ────────────────────────────────────────────────────
        val getpropAfterRaw = shell.exec("getprop", preferRoot = true, timeoutMs = 10_000L).stdout
        File(dumpsDir, "getprop_apres.txt").writeText(getpropAfterRaw)
        val afterProps = parseProps(getpropAfterRaw)

        val lshalAfter = if (rootInfo.isGranted) {
            shell.exec("lshal --neat -i -t 2>/dev/null; echo '---SERVICE_LIST---'; service list 2>/dev/null", preferRoot = true, timeoutMs = 10_000L).stdout
        } else {
            "Mode non-root : lshal restreint"
        }
        File(dumpsDir, "apres_lshal_et_services.txt").writeText(lshalAfter)

        val afterDumpsys = captureKeyDumpsys(rootInfo.isGranted)
        afterDumpsys.forEach { (k, v) ->
            File(dumpsDir, "apres_dumpsys_${k}.txt").writeText(v)
        }

        val protectedAfter = auditProtectedMetadataSafe(rootInfo.isGranted)
        File(dumpsDir, "apres_zones_protegees.txt").writeText(protectedAfter)

        val sysfsFinalMap = readSysfsBatch(sysfsNodesToWatch, rootInfo.isGranted)
        File(dumpsDir, "sysfs_apres.txt").writeText(
            sysfsFinalMap.entries.joinToString("\n") { "${it.key} = ${it.value}" }
        )

        // Sauvegarder détails /proc HAL & IPC Binder
        val halSnapshots = halSnapshotsMap.values.toList()
        File(dumpsDir, "hal_proc_et_binder.txt").writeText(buildString {
            halSnapshots.forEach { h ->
                appendLine("=== PID=${h.pid} | ${h.processName} | UID=${h.uid} | ${h.seLinuxContext} ===")
                appendLine("Cmdline: ${h.cmdline}")
                appendLine("-- Open FDs (${h.openFds.size}) --")
                h.openFds.forEach { appendLine("  $it") }
                appendLine("-- Mapped files (${h.mappedFiles.size}) --")
                h.mappedFiles.forEach { appendLine("  $it") }
                appendLine("-- Unix sockets (${h.unixSockets.size}) --")
                h.unixSockets.forEach { appendLine("  $it") }
                if (h.straceHighlights.isNotEmpty()) {
                    appendLine("-- Strace highlights --")
                    h.straceHighlights.forEach { appendLine("  $it") }
                }
                appendLine()
            }
            if (rootInfo.isGranted) {
                val binderInfo = shell.exec(
                    "head -n 120 /sys/kernel/debug/binder/state /dev/binderfs/binder_logs/state 2>/dev/null | grep -iE 'proc|fingerprint|biometric|display|touch|systemui|surfaceflinger' | head -n 120",
                    preferRoot = true,
                    timeoutMs = 4_000L
                ).stdout
                if (binderInfo.isNotBlank()) {
                    appendLine("=== EXTRAITS BINDER IPC ===")
                    appendLine(binderInfo)
                }
            }
        })

        // Construire LiveSysfsTransition + Delta Avant/Après
        val sysfsTransitionsList = sysfsNodesToWatch.mapNotNull { path ->
            val before = sysfsInitialMap[path] ?: return@mapNotNull null
            val during = sysfsHistory[path].orEmpty()
            val after = sysfsFinalMap[path] ?: before
            val changed = before != after || during.distinct().size > 1
            val lsZ = shell.exec("ls -ldZ ${RootShellExecutor.shellQuote(path)} 2>/dev/null", preferRoot = rootInfo.isGranted, timeoutMs = 1_500L).stdout.trim()
            val parts = lsZ.split(Regex("\\s+"))
            LiveSysfsTransition(
                path = path,
                category = categorizeSysfsPath(path),
                beforeValue = before,
                duringValues = during.distinct().take(10),
                afterValue = after,
                hasChanged = changed,
                permissions = parts.firstOrNull() ?: "?",
                seLinuxContext = parts.firstOrNull { it.startsWith("u:object_r:") } ?: "?"
            )
        }

        val deltaSummary = buildBeforeAfterDelta(
            beforeProps = beforeProps,
            afterProps = afterProps,
            beforeDumpsys = beforeDumpsys,
            afterDumpsys = afterDumpsys,
            sysfsTransitions = sysfsTransitionsList,
            protectedBefore = protectedBefore,
            protectedAfter = protectedAfter
        )
        File(dumpsDir, "delta_avant_apres.txt").writeText(deltaSummary)

        // ── EXTRACTION CHAÎNE + CODE SOURCE + SYNTHÈSE MÉCANISME & PATCHS ─────────
        val extraction = extractor.extractChainAndReconstructSources(
            LiveExtractionInput(
                sessionDir = sessionDir,
                discoveredPathsWithReason = discoveredPaths.toMap(),
                halProcesses = halSnapshots,
                sysfsTransitions = sysfsTransitionsList,
                timelineEvents = timelineEvents.toList(),
                beforeProps = beforeProps,
                afterProps = afterProps,
                beforeLshal = lshalBefore,
                afterLshal = lshalAfter,
                beforeDumpsys = beforeDumpsys,
                duringDumpsys = liveDuringDumpsys.toMap(),
                afterDumpsys = afterDumpsys,
                avcLines = avcLines.toList(),
                protectedAreasReport = "$protectedBefore\n\nAPRÈS:\n$protectedAfter",
                dmesgLines = dmesgAllLines.toList()
            )
        ) { status ->
            onHudUpdate { it.copy(lastLiveHeadline = status) }
        }

        val durationSec = maxOf(1L, (System.currentTimeMillis() - startMs) / 1000L)
        val rawManifest = linkedMapOf<String, String>()
        sessionDir.walkTopDown().filter { it.isFile }.forEach { f ->
            val rel = f.relativeTo(sessionDir).path
            rawManifest[rel] = rel
        }

        val metadata = LiveSessionMetadata(
            id = sessionId,
            displayName = sessionLabel.ifBlank { "${romType.labelFr} — $stamp" },
            romType = romType,
            isImported = false,
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
            androidVersion = Build.VERSION.RELEASE ?: "?",
            sdkInt = Build.VERSION.SDK_INT,
            buildFingerprint = beforeProps["ro.build.fingerprint"] ?: Build.FINGERPRINT,
            vendorFingerprint = beforeProps["ro.vendor.build.fingerprint"] ?: "Inconnu",
            isDsuActive = isDsuActive,
            rootGranted = rootInfo.isGranted,
            rootProvider = rootInfo.provider,
            startedAtIso = iso,
            durationSec = durationSec,
            sessionDirPath = sessionDir.absolutePath,
            totalRawLogLines = rawLogcatCount.get(),
            totalTimelineEvents = timelineEvents.size,
            extractedFilesCount = extraction.extractedFiles.size,
            reconstructedSourcesCount = extraction.extractedFiles.count { it.sourceCodeRelPath != null },
            patchesCount = extraction.patches.size,
            detectedVerdict = extraction.mechanism.enrollmentVerdict
        )

        val reportMd = buildMechanismMarkdown(
            meta = metadata,
            mechanism = extraction.mechanism,
            sysfsTransitions = sysfsTransitionsList,
            halProcesses = halSnapshots,
            files = extraction.extractedFiles,
            patches = extraction.patches,
            deltaSummary = deltaSummary
        )

        val session = LiveFodSession(
            metadata = metadata,
            mechanism = extraction.mechanism,
            timelineEvents = timelineEvents.toList(),
            sysfsTransitions = sysfsTransitionsList.sortedByDescending { it.hasChanged },
            halProcesses = halSnapshots,
            extractedFiles = extraction.extractedFiles,
            patches = extraction.patches,
            rawFilesManifest = rawManifest,
            beforeAfterDeltaSummary = deltaSummary,
            reportMarkdown = reportMd
        )

        storage.saveSession(session)
        onHudUpdate {
            it.copy(
                phase = LiveCapturePhase.COMPLETED,
                elapsedSeconds = durationSec,
                lastLiveHeadline = "Session sauvegardée : ${metadata.extractedFilesCount} fichiers, ${metadata.patchesCount} patchs"
            )
        }
        session
    }

    private suspend fun captureKeyDumpsys(isRoot: Boolean): Map<String, String> {
        val services = listOf("fingerprint", "biometric", "SurfaceFlinger", "display", "overlay", "power", "activity")
        val out = LinkedHashMap<String, String>()
        for (svc in services) {
            val cmd = when (svc) {
                "SurfaceFlinger" -> "dumpsys SurfaceFlinger 2>/dev/null | head -n 260"
                "activity" -> "dumpsys activity top 2>/dev/null | head -n 140"
                "overlay" -> "dumpsys overlay 2>/dev/null | grep -iE 'fp|fod|udfps|finger|biometric|systemui|\\[x\\]' -B1 -A2 | head -n 220"
                else -> "dumpsys $svc 2>/dev/null | head -n 300"
            }
            val res = shell.exec(cmd, preferRoot = isRoot, timeoutMs = 5_000L)
            out[svc] = res.stdout.ifBlank { res.stderr.ifBlank { "(aucune sortie)" } }
        }
        return out
    }

    private suspend fun discoverUniversalSysfsNodes(isRoot: Boolean): MutableList<String> {
        val cmd = """
            for root in /sys/class/drm /sys/class/backlight /sys/class/leds /sys/devices/platform /sys/devices/virtual; do
              if [ -e "${'$'}root" ]; then
                find "${'$'}root" -maxdepth 4 -type f 2>/dev/null | grep -iE 'hbm|lhbm|fod|udfps|finger|dim|alpha|bright|disp|panel|doze|touch|irq|state|mode|goodix|fpc|silead|sec_fp' | head -n 60
              fi
            done
        """.trimIndent()
        val res = shell.exec(cmd, preferRoot = isRoot, timeoutMs = 8_000L)
        return res.stdout.lines()
            .map { it.trim() }
            .filter { it.startsWith("/sys/") && !BiometricPrivacyGuard.isProtectedBiometricPath(it) }
            .distinct()
            .take(140)
            .toMutableList()
    }

    private suspend fun readSysfsBatch(paths: List<String>, isRoot: Boolean): Map<String, String> {
        if (paths.isEmpty()) return emptyMap()
        val result = LinkedHashMap<String, String>()
        // Lire par lots de 35 pour éviter de lancer trop de sous-shells
        paths.chunked(35).forEach { batch ->
            val script = buildString {
                batch.forEach { p ->
                    val q = RootShellExecutor.shellQuote(p)
                    append("if [ -r $q ]; then v=$(head -c 160 $q 2>/dev/null | tr '\\n\\r\\0' '   '); echo \"SYSFS::$p::${'$'}v\"; fi\n")
                }
            }
            val out = shell.exec(script, preferRoot = isRoot, timeoutMs = 4_500L).stdout
            out.lines().forEach { line ->
                if (line.startsWith("SYSFS::")) {
                    val rest = line.removePrefix("SYSFS::")
                    val idx = rest.indexOf("::")
                    if (idx > 0) {
                        result[rest.substring(0, idx)] = rest.substring(idx + 2).trim()
                    }
                }
            }
        }
        return result
    }

    private suspend fun auditProtectedMetadataSafe(isRoot: Boolean): String {
        val cmd = """
            for p in /data/vendor_de/0/fpdata /data/system/users/0/fpdata /data/misc/keystore /data/vendor/tee /mnt/vendor/persist /dev/qseecom /dev/tee0 /dev/goodix_fp /dev/esfp0; do
              if [ -e "${'$'}p" ]; then
                ls -ldZ "${'$'}p" 2>/dev/null
              else
                echo "ABSENT: ${'$'}p"
              fi
            done
        """.trimIndent()
        return shell.exec(cmd, preferRoot = isRoot, timeoutMs = 4_000L).stdout
    }

    private suspend fun inspectProcessProcDeep(pid: String, name: String): LiveHalProcessSnapshot {
        val statusOut = shell.exec("grep -E '^(Uid|Pid|Threads):' /proc/$pid/status 2>/dev/null; cat /proc/$pid/attr/current 2>/dev/null; echo '---CMD---'; tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null", preferRoot = true, timeoutMs = 2_000L).stdout
        val uid = Regex("""Uid:\s*(\d+)""").find(statusOut)?.groupValues?.getOrNull(1) ?: "?"
        val seCtx = statusOut.lines().firstOrNull { it.contains("u:r:") }?.trim() ?: "?"
        val cmdline = statusOut.substringAfter("---CMD---", "").trim().ifBlank { name }

        val fdsOut = shell.exec("ls -l /proc/$pid/fd 2>/dev/null | head -n 70", preferRoot = true, timeoutMs = 2_000L).stdout
        val openFds = fdsOut.lines().filter { it.contains("->") }.map { it.substringAfterLast(" ", "").trim().let { _ -> it.trim() } }.take(60)

        val mapsOut = shell.exec("awk '{print \$6}' /proc/$pid/maps 2>/dev/null | grep -E '^/' | sort -u | head -n 120", preferRoot = true, timeoutMs = 2_500L).stdout
        val mapped = mapsOut.lines().map { it.trim() }.filter { it.startsWith("/") }.distinct()

        val sockOut = shell.exec("grep -iE 'finger|biometric|display|touch|goodix|keystore|gatekeeper' /proc/net/unix 2>/dev/null | head -n 25", preferRoot = true, timeoutMs = 2_000L).stdout
        val sockets = sockOut.lines().filter { it.isNotBlank() }

        return LiveHalProcessSnapshot(
            pid = pid,
            processName = name,
            uid = uid,
            seLinuxContext = seCtx,
            cmdline = cmdline,
            openFds = openFds,
            mappedFiles = mapped,
            unixSockets = sockets,
            straceHighlights = emptyList()
        )
    }

    private fun collectCandidatePidsFromPs(psOut: String): MutableMap<String, String> {
        val map = LinkedHashMap<String, String>()
        psOut.lines().forEach { line ->
            val lower = line.lowercase()
            if (lower.contains("finger") || lower.contains("biometric") || lower.contains("goodix") ||
                lower.contains("fpc") || lower.contains("silead") || lower.contains("focal") ||
                lower.contains("display") || lower.contains("touch") || lower.contains("surfaceflinger") ||
                lower.contains("systemui") || lower.contains("keystore") || lower.contains("gatekeeper") ||
                lower.contains("tee") || lower.contains("qsee")
            ) {
                val tokens = line.trim().split(Regex("\\s+"))
                val pid = tokens.firstOrNull { it.all(Char::isDigit) && it.length in 1..6 }
                val cmd = tokens.lastOrNull().orEmpty()
                if (pid != null && cmd.isNotBlank()) {
                    map[pid] = cmd
                }
            }
        }
        return map
    }

    private fun isRelevantLiveLogcatLine(line: String, activePids: Set<String>): Boolean {
        val l = line.lowercase()
        val pid = extractPidFromThreadtime(line)
        if (pid != null && pid in activePids && (l.contains("fod") || l.contains("fp") || l.contains("udfps") || l.contains("hbm") || l.contains("enroll") || l.contains("error") || l.contains("fail") || l.contains("ioctl"))) {
            return true
        }
        return l.contains("fingerprint") || l.contains("biometric") || l.contains("udfps") ||
            l.contains("fod") || l.contains("goodix") || l.contains("gf_hal") ||
            l.contains("silead") || l.contains("egistec") || l.contains("fpc_") ||
            l.contains("hbm") || l.contains("lhbm") || l.contains("displayfeature") ||
            l.contains("touchfeature") || l.contains("onacquired") || l.contains("onenroll") ||
            l.contains("avc: denied") || l.contains("keystore") || l.contains("gatekeeper")
    }

    private fun extractPidFromThreadtime(line: String): String? {
        return Regex("""^\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+\s+(\d+)\s+\d+""").find(line)?.groupValues?.getOrNull(1)
    }

    private fun extractTagFromThreadtime(line: String): String {
        return Regex("""^\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+\s+\d+\s+\d+\s+[VDIWEFA]\s+([^\s:]+)""").find(line)?.groupValues?.getOrNull(1) ?: "System"
    }

    private fun classifyLogcatLineOutcome(line: String): LiveOutcome {
        val l = line.lowercase()
        return when {
            l.contains("avc: denied") || l.contains("error") || l.contains("fail") ||
                l.contains("exception") || l.contains("denied") || l.contains("unavailable") ||
                l.contains("eacces") || l.contains("enoent") -> LiveOutcome.ERREUR_EXPLICITE
            l.contains("enroll") || l.contains("onacquired") || l.contains("fingerdown") ||
                l.contains("fingerup") || l.contains("hbm") || l.contains("illuminat") -> LiveOutcome.REACTION_DETECTEE
            else -> LiveOutcome.INFO_TECHNIQUE
        }
    }

    private fun isInterestingKernelLine(line: String): Boolean {
        val l = line.lowercase()
        return l.contains("finger") || l.contains("goodix") || l.contains("fpc") ||
            l.contains("silead") || l.contains("fod") || l.contains("udfps") ||
            l.contains("hbm") || l.contains("lhbm") || l.contains("drm") ||
            l.contains("dsi") || l.contains("touch") || l.contains("tee") ||
            l.contains("qsee") || l.contains("avc:")
    }

    private fun classifyKernelOutcome(line: String): LiveOutcome {
        val l = line.lowercase()
        return if (l.contains("err") || l.contains("fail") || l.contains("denied") || l.contains("timeout")) {
            LiveOutcome.ERREUR_EXPLICITE
        } else {
            LiveOutcome.REACTION_DETECTEE
        }
    }

    private fun extractFilePathsFromText(text: String): List<String> {
        return Regex("""(/(?:vendor|system|system_ext|product|odm|apex|data|sys|dev)/[a-zA-Z0-9_./+-]+)""")
            .findAll(text)
            .map { it.groupValues[1] }
            .distinct()
            .toList()
    }

    private fun categorizeSysfsPath(path: String): String = when {
        path.contains("drm") || path.contains("backlight") || path.contains("hbm") || path.contains("disp") || path.contains("panel") -> "Affichage / HBM"
        path.contains("touch") || path.contains("input") -> "Tactile"
        path.contains("finger") || path.contains("goodix") || path.contains("fpc") || path.contains("fod") -> "Capteur FOD"
        else -> "Matériel / Plateforme"
    }

    private fun parseProps(raw: String): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        val rx = Regex("""^\[([^\]]+)\]:\s*\[(.*)\]$""")
        raw.lines().forEach { line ->
            rx.find(line.trim())?.let { m -> map[m.groupValues[1]] = m.groupValues[2] }
        }
        return map
    }

    private fun buildBeforeAfterDelta(
        beforeProps: Map<String, String>,
        afterProps: Map<String, String>,
        beforeDumpsys: Map<String, String>,
        afterDumpsys: Map<String, String>,
        sysfsTransitions: List<LiveSysfsTransition>,
        protectedBefore: String,
        protectedAfter: String
    ): String {
        val sb = StringBuilder()
        sb.appendLine("=== DELTA FACTUEL AVANT (T0) -> APRÈS (T_fin) ===")
        sb.appendLine()
        val changedProps = (beforeProps.keys + afterProps.keys).distinct().filter { beforeProps[it] != afterProps[it] }
        sb.appendLine("[1. PROPRIÉTÉS MODIFIÉES PENDANT L'ENRÔLEMENT (${changedProps.size})]")
        if (changedProps.isEmpty()) sb.appendLine("- Aucune propriété système modifiée")
        changedProps.take(50).forEach { k ->
            sb.appendLine("- $k : '${beforeProps[k] ?: "<absent>"}' -> '${afterProps[k] ?: "<absent>"}'")
        }
        sb.appendLine()
        val changedSysfs = sysfsTransitions.filter { it.hasChanged }
        sb.appendLine("[2. NŒUDS SYSFS AYANT TRANSITÉ (${changedSysfs.size}/${sysfsTransitions.size})]")
        if (changedSysfs.isEmpty()) sb.appendLine("- Aucun nœud sysfs n'a changé d'état durant la capture")
        changedSysfs.forEach { t ->
            sb.appendLine("- ${t.path} : avant='${t.beforeValue}' -> pendant=${t.duringValues} -> après='${t.afterValue}' (${t.permissions} | ${t.seLinuxContext})")
        }
        sb.appendLine()
        sb.appendLine("[3. DIFFÉRENCES DUMPSYS FINGERPRINT / SURFACEFLINGER]")
        listOf("fingerprint", "biometric", "SurfaceFlinger").forEach { svc ->
            val bLines = beforeDumpsys[svc].orEmpty().lines().toSet()
            val aLines = afterDumpsys[svc].orEmpty().lines().filter { it.isNotBlank() && it !in bLines }
            sb.appendLine("-- Nouvelles lignes dans dumpsys $svc (${aLines.size}) --")
            aLines.take(35).forEach { sb.appendLine("  + $it") }
        }
        sb.appendLine()
        sb.appendLine("[4. ZONES PROTÉGÉES (MÉTADONNÉES UNIQUEMENT)]")
        if (protectedBefore == protectedAfter) {
            sb.appendLine("- Métadonnées structurelles identiques avant/après.")
        } else {
            sb.appendLine("AVANT:\n$protectedBefore\nAPRÈS:\n$protectedAfter")
        }
        return sb.toString()
    }

    private fun buildMechanismMarkdown(
        meta: LiveSessionMetadata,
        mechanism: LiveDiscoveredMechanism,
        sysfsTransitions: List<LiveSysfsTransition>,
        halProcesses: List<LiveHalProcessSnapshot>,
        files: List<LiveExtractedFileRecord>,
        patches: List<LiveGeneratedPatch>,
        deltaSummary: String
    ): String {
        val sb = StringBuilder()
        sb.appendLine("# LIVE FOD — SYNTHÈSE BRUTE & MÉCANISME DÉTECTÉ")
        sb.appendLine()
        sb.appendLine("- **Session** : `${meta.displayName}` (`${meta.id}`)")
        sb.appendLine("- **Environnement** : `${meta.romType.labelFr}` | Appareil `${meta.deviceModel}` (Android ${meta.androidVersion})")
        sb.appendLine("- **Durée** : `${meta.durationSec}s` | Root : `${meta.rootProvider}`")
        sb.appendLine("- **Verdict d'enrôlement** : **${mechanism.enrollmentVerdict}**")
        sb.appendLine("- **Architecture détectée** : `${mechanism.primaryArchitecture}`")
        sb.appendLine("- **Illumination observée** : ${mechanism.displayIlluminationMethod}")
        sb.appendLine("- **Tactile observé** : ${mechanism.touchInteractionMethod}")
        sb.appendLine()
        sb.appendLine("## 1. Chaîne d'interaction réelle (étape par étape)")
        mechanism.hops.forEach { h ->
            sb.appendLine("### Étape ${h.order} : ${h.hopName} [${h.outcome.labelFr}]")
            sb.appendLine("- **Preuve factuelle** : ${h.factualEvidence}")
            sb.appendLine("- **Acteurs observés** : ${h.actorsObserved.joinToString(", ").ifBlank { "Aucun" }}")
            sb.appendLine("- **Fichiers / Nœuds** : ${h.filesAndNodesInvolved.joinToString(", ").ifBlank { "Aucun" }}")
            sb.appendLine()
        }
        sb.appendLine("## 2. Processus HAL / Display / Touch inspectés via /proc (${halProcesses.size})")
        halProcesses.forEach { p ->
            sb.appendLine("- **${p.processName}** (PID=${p.pid}, UID=${p.uid}, SELinux=`${p.seLinuxContext}`) : ${p.mappedFiles.size} libs mappées, ${p.openFds.size} FDs")
        }
        sb.appendLine()
        sb.appendLine("## 3. Transitions Sysfs observées (${sysfsTransitions.count { it.hasChanged }} / ${sysfsTransitions.size})")
        sysfsTransitions.filter { it.hasChanged }.forEach { t ->
            sb.appendLine("- `${t.path}` : `${t.beforeValue}` ➔ ${t.duringValues} ➔ `${t.afterValue}`")
        }
        sb.appendLine()
        sb.appendLine("## 4. Fichiers de la chaîne extraits & codes sources (${files.size})")
        files.take(60).forEach { f ->
            sb.appendLine("- `${f.originalPath}` (`${f.category}`) | Source=`${f.sourceCodeRelPath ?: "N/A"}` | Raison : ${f.reasonInChain}")
        }
        sb.appendLine()
        sb.appendLine("## 5. Patchs générés (${patches.size})")
        patches.forEach { p ->
            sb.appendLine("- `${p.fileName}` (${p.kind}) → `${p.targetPathHint}` : ${p.description}")
        }
        sb.appendLine()
        sb.appendLine("## 6. Delta Avant / Après")
        sb.appendLine("```")
        sb.appendLine(deltaSummary)
        sb.appendLine("```")
        return sb.toString()
    }
}

package com.example.livefod

import android.content.Context
import android.net.Uri
import android.os.Environment
import com.example.model.RomEnvironmentType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class LiveFodStorageManager(private val context: Context) {

    fun getPrimarySdcardRoot(): File = File(Environment.getExternalStorageDirectory(), "FOD Database")

    fun getActiveDatabaseDir(): File {
        val primary = getPrimarySdcardRoot()
        if (ensureWritableDir(primary)) return primary
        val appExt = File(context.getExternalFilesDir(null) ?: context.filesDir, "FOD Database")
        ensureWritableDir(appExt)
        return appExt
    }

    fun getLiveSessionsRootDir(): File {
        return File(getActiveDatabaseDir(), "LiveFodSessions").apply { mkdirs() }
    }

    fun getExportsDir(): File {
        return File(getActiveDatabaseDir(), "Exports").apply { mkdirs() }
    }

    fun prepareNewSessionWorkingDir(sessionId: String): File {
        val dir = File(getLiveSessionsRootDir(), sessionId)
        dir.mkdirs()
        File(dir, "02_logs_bruts").mkdirs()
        File(dir, "03_dumpsys_et_ipc").mkdirs()
        File(dir, "04_artefacts_extraits").mkdirs()
        File(dir, "05_code_source_reconstruit").mkdirs()
        File(dir, "06_patchs_et_imitation").mkdirs()
        return dir
    }

    private fun ensureWritableDir(dir: File): Boolean {
        return runCatching {
            if (!dir.exists()) dir.mkdirs()
            if (!dir.exists() || !dir.isDirectory) return@runCatching false
            val probe = File(dir, ".write_test_${System.nanoTime()}")
            probe.writeText("ok")
            val ok = probe.exists()
            probe.delete()
            ok
        }.getOrDefault(false)
    }

    suspend fun saveSession(session: LiveFodSession): LiveFodSession = withContext(Dispatchers.IO) {
        val sessionDir = File(session.metadata.sessionDirPath).apply { mkdirs() }
        File(sessionDir, "02_logs_bruts").mkdirs()
        File(sessionDir, "03_dumpsys_et_ipc").mkdirs()
        File(sessionDir, "04_artefacts_extraits").mkdirs()
        File(sessionDir, "05_code_source_reconstruit").mkdirs()
        val patchesDir = File(sessionDir, "06_patchs_et_imitation").apply { mkdirs() }

        // 00_MECANISME_FOD_DETECTE.md
        File(sessionDir, "00_MECANISME_FOD_DETECTE.md").writeText(session.reportMarkdown)

        // 01_CHAINE_INTERACTION_COMPLETE.txt & .json
        val chainTxt = buildString {
            appendLine("=== CHAÎNE D'INTERACTION OBSERVÉE (${session.metadata.displayName}) ===")
            appendLine("Architecture détectée : ${session.mechanism.primaryArchitecture}")
            appendLine("Verdict enrôlement : ${session.mechanism.enrollmentVerdict}")
            appendLine()
            session.mechanism.hops.forEach { hop ->
                appendLine("[Étape ${hop.order}] ${hop.hopName} (${hop.layerTag}) -> ${hop.outcome.labelFr}")
                appendLine("  Acteurs : ${hop.actorsObserved.joinToString(", ").ifBlank { "Aucun" }}")
                appendLine("  Fichiers/Nœuds : ${hop.filesAndNodesInvolved.joinToString(", ").ifBlank { "Aucun" }}")
                appendLine("  Preuve : ${hop.factualEvidence}")
                appendLine()
            }
            appendLine("=== CHRONOLOGIE DÉTAILLÉE (${session.timelineEvents.size} événements) ===")
            session.timelineEvents.forEach { ev ->
                appendLine("[${ev.relativeTimeLabel}] [${ev.source.labelFr}] [${ev.outcome.labelFr}] ${ev.actor} : ${ev.summary}")
                if (ev.rawDetail.isNotBlank() && ev.rawDetail != ev.summary) {
                    appendLine("    ${ev.rawDetail.take(400)}")
                }
            }
        }
        File(sessionDir, "01_CHAINE_INTERACTION_COMPLETE.txt").writeText(chainTxt)

        val chainJson = JSONObject()
            .put("mechanism", serializeMechanism(session.mechanism))
            .put("timelineEvents", JSONArray().apply {
                session.timelineEvents.forEach { put(serializeEvent(it)) }
            })
            .put("sysfsTransitions", JSONArray().apply {
                session.sysfsTransitions.forEach { put(serializeSysfs(it)) }
            })
            .put("halProcesses", JSONArray().apply {
                session.halProcesses.forEach { put(serializeHalProc(it)) }
            })
            .put("extractedFiles", JSONArray().apply {
                session.extractedFiles.forEach { put(serializeExtractedFile(it)) }
            })
            .put("patches", JSONArray().apply {
                session.patches.forEach { put(serializePatch(it)) }
            })
            .put("beforeAfterDeltaSummary", session.beforeAfterDeltaSummary)
        File(sessionDir, "01_CHAINE_INTERACTION_COMPLETE.json").writeText(chainJson.toString(2))

        // 06_patchs_et_imitation/
        session.patches.forEach { p ->
            File(patchesDir, p.fileName).writeText(p.codeContent)
        }

        // manifest_live_fod.json
        val rawMapObj = JSONObject()
        session.rawFilesManifest.forEach { (k, v) -> rawMapObj.put(k, v) }
        val manifestObj = JSONObject()
            .put("metadata", serializeMetadata(session.metadata))
            .put("rawFilesManifest", rawMapObj)
        File(sessionDir, "manifest_live_fod.json").writeText(manifestObj.toString(2))

        session
    }

    suspend fun listAllSessions(): List<LiveFodSession> = withContext(Dispatchers.IO) {
        val root = getLiveSessionsRootDir()
        val dirs = root.listFiles()?.filter { it.isDirectory && File(it, "manifest_live_fod.json").exists() }
            ?: return@withContext emptyList()
        dirs.mapNotNull { loadSessionFromDir(it) }
            .sortedByDescending { it.metadata.startedAtIso }
    }

    suspend fun deleteSession(session: LiveFodSession): Boolean = withContext(Dispatchers.IO) {
        val dir = File(session.metadata.sessionDirPath)
        if (dir.exists()) dir.deleteRecursively() else false
    }

    suspend fun exportSessionToZip(session: LiveFodSession): File = withContext(Dispatchers.IO) {
        val sessionDir = File(session.metadata.sessionDirPath)
        val exportsDir = getExportsDir()
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val zipFile = File(exportsDir, "LIVE_FOD_${session.metadata.id}_$stamp.zip")
        ZipOutputStream(BufferedOutputStream(FileOutputStream(zipFile))).use { zos ->
            zipFolderRecursive(sessionDir, session.metadata.id, zos)
        }
        val updatedMeta = session.metadata.copy(zipExportPath = zipFile.absolutePath)
        val manifestFile = File(sessionDir, "manifest_live_fod.json")
        if (manifestFile.exists()) {
            runCatching {
                val obj = JSONObject(manifestFile.readText())
                obj.put("metadata", serializeMetadata(updatedMeta))
                manifestFile.writeText(obj.toString(2))
            }
        }
        zipFile
    }

    suspend fun exportLiveComparisonToZip(
        report: LiveComparisonReport,
        sessionA: LiveFodSession,
        sessionB: LiveFodSession
    ): File = withContext(Dispatchers.IO) {
        val exportsDir = getExportsDir()
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val stagingDir = File(exportsDir, "tmp_live_cmp_$stamp").apply { mkdirs() }
        try {
            File(stagingDir, "RAPPORT_COMPARAISON_LIVE_FOD.md").writeText(report.reportMarkdown)
            val patchesDir = File(stagingDir, "patchs_differentiels").apply { mkdirs() }
            report.differentialPatches.forEach { p ->
                File(patchesDir, p.fileName).writeText(p.codeContent)
            }

            val jsonObj = JSONObject()
                .put("sessionA", serializeMetadata(report.sessionA))
                .put("sessionB", serializeMetadata(report.sessionB))
                .put("causalSummaryFr", report.causalSummaryFr)
                .put("blockersCount", report.blockersCount)
                .put("items", JSONArray().apply {
                    report.items.forEach { item ->
                        put(
                            JSONObject()
                                .put("domain", item.domain)
                                .put("subject", item.subject)
                                .put("valueInA", item.valueInA)
                                .put("valueInB", item.valueInB)
                                .put("isCriticalBlocker", item.isCriticalBlocker)
                                .put("factualExplanation", item.factualExplanation)
                                .put("imitationAction", item.imitationAction)
                        )
                    }
                })
            File(stagingDir, "comparaison_live_data.json").writeText(jsonObj.toString(2))

            // Inclure mécanisme, chaîne, patchs et code source reconstruit de la session A (référence)
            val refA = File(stagingDir, "reference_session_A").apply { mkdirs() }
            val dirA = File(sessionA.metadata.sessionDirPath)
            listOf(
                "00_MECANISME_FOD_DETECTE.md",
                "01_CHAINE_INTERACTION_COMPLETE.txt",
                "05_code_source_reconstruit",
                "06_patchs_et_imitation"
            ).forEach { rel ->
                val src = File(dirA, rel)
                if (src.exists()) src.copyRecursively(File(refA, rel), overwrite = true)
            }
            val refB = File(stagingDir, "cible_session_B").apply { mkdirs() }
            val dirB = File(sessionB.metadata.sessionDirPath)
            listOf(
                "00_MECANISME_FOD_DETECTE.md",
                "01_CHAINE_INTERACTION_COMPLETE.txt"
            ).forEach { rel ->
                val src = File(dirB, rel)
                if (src.exists()) src.copyRecursively(File(refB, rel), overwrite = true)
            }

            val zipFile = File(exportsDir, "COMPARAISON_LIVE_FOD_$stamp.zip")
            ZipOutputStream(BufferedOutputStream(FileOutputStream(zipFile))).use { zos ->
                zipFolderRecursive(stagingDir, "COMPARAISON_LIVE_FOD_$stamp", zos)
            }
            zipFile
        } finally {
            stagingDir.deleteRecursively()
        }
    }

    suspend fun importLiveZipFromUri(uri: Uri): Result<LiveFodSession> = withContext(Dispatchers.IO) {
        runCatching {
            val liveRoot = getLiveSessionsRootDir()
            val stagingDir = File(liveRoot, "IMPORT_LIVE_${System.currentTimeMillis()}").apply { mkdirs() }
            val input = context.contentResolver.openInputStream(uri)
                ?: throw IllegalStateException("Impossible d'ouvrir le fichier .zip sélectionné.")

            var count = 0
            ZipInputStream(BufferedInputStream(input)).use { zis ->
                val canonicalRoot = stagingDir.canonicalPath
                while (true) {
                    val entry = zis.nextEntry ?: break
                    val outFile = File(stagingDir, entry.name)
                    val canonicalOut = outFile.canonicalPath
                    if (!canonicalOut.startsWith(canonicalRoot + File.separator) && canonicalOut != canonicalRoot) {
                        throw SecurityException("Entrée ZIP non sécurisée (Zip Slip) : ${entry.name}")
                    }
                    if (entry.isDirectory) {
                        outFile.mkdirs()
                    } else {
                        outFile.parentFile?.mkdirs()
                        FileOutputStream(outFile).use { fos -> zis.copyTo(fos) }
                        count++
                    }
                    zis.closeEntry()
                }
            }
            if (count == 0) {
                stagingDir.deleteRecursively()
                throw IllegalArgumentException("L'archive .zip sélectionnée est vide.")
            }

            val sessionDir = findLiveManifestDir(stagingDir)
                ?: throw IllegalArgumentException(
                    "Archive décompressée, mais aucun manifest_live_fod.json Live FOD n'a été détecté."
                )

            val finalDir = if (sessionDir != stagingDir) {
                val targetName = "${sessionDir.name}_imp_${System.currentTimeMillis() % 10000}"
                val dest = File(liveRoot, targetName)
                if (sessionDir.renameTo(dest)) {
                    stagingDir.deleteRecursively()
                    dest
                } else {
                    sessionDir
                }
            } else {
                stagingDir
            }

            val loaded = loadSessionFromDir(finalDir)
                ?: throw IllegalStateException("Impossible de lire les données de la session Live FOD importée.")
            val importedId = if (loaded.metadata.isImported) loaded.metadata.id else "${loaded.metadata.id}_imp"
            val updatedMeta = loaded.metadata.copy(
                id = importedId,
                isImported = true,
                displayName = if (loaded.metadata.displayName.contains("[Importé]")) {
                    loaded.metadata.displayName
                } else {
                    "[Importé] ${loaded.metadata.displayName}"
                },
                sessionDirPath = finalDir.absolutePath
            )
            val manifestFile = File(finalDir, "manifest_live_fod.json")
            val obj = JSONObject(manifestFile.readText())
            obj.put("metadata", serializeMetadata(updatedMeta))
            manifestFile.writeText(obj.toString(2))
            loaded.copy(metadata = updatedMeta)
        }
    }

    fun readSessionSubFilePreview(session: LiveFodSession, relativePath: String, maxChars: Int = 36_000): String {
        val dir = File(session.metadata.sessionDirPath)
        val clean = relativePath.trimStart('/')
        if (clean.contains("..")) return "Chemin invalide."
        val f = File(dir, clean)
        if (!f.exists() || !f.isFile) return "Fichier introuvable : $relativePath"
        return runCatching {
            val text = f.readText()
            if (text.length > maxChars) {
                text.take(maxChars) + "\n\n... [tronqué pour affichage, complet sur disque : ${f.absolutePath}]"
            } else {
                text
            }
        }.getOrElse { "Contenu binaire (${f.length()} octets) : ${f.absolutePath}" }
    }

    private fun loadSessionFromDir(dir: File): LiveFodSession? = runCatching {
        val manifestObj = JSONObject(File(dir, "manifest_live_fod.json").readText())
        val meta = deserializeMetadata(manifestObj.getJSONObject("metadata"), dir.absolutePath)
        val rawMap = LinkedHashMap<String, String>()
        manifestObj.optJSONObject("rawFilesManifest")?.let { rm ->
            rm.keys().forEach { k -> rawMap[k] = rm.optString(k) }
        }
        // Fallback scan for any extra files inside subdirectories
        listOf("00_MECANISME_FOD_DETECTE.md", "01_CHAINE_INTERACTION_COMPLETE.txt").forEach { top ->
            val tf = File(dir, top)
            if (tf.exists() && !rawMap.containsKey(top)) rawMap[top] = top
        }
        dir.listFiles()?.filter { it.isDirectory }?.forEach { sub ->
            sub.walkTopDown().filter { it.isFile }.take(120).forEach { f ->
                val rel = f.relativeTo(dir).path
                if (!rawMap.containsKey(rel)) rawMap[rel] = rel
            }
        }

        val chainFile = File(dir, "01_CHAINE_INTERACTION_COMPLETE.json")
        val chainObj = if (chainFile.exists()) JSONObject(chainFile.readText()) else JSONObject()
        val mechanism = deserializeMechanism(chainObj.optJSONObject("mechanism"))
        val events = mutableListOf<LiveInteractionEvent>()
        chainObj.optJSONArray("timelineEvents")?.let { arr ->
            for (i in 0 until arr.length()) events.add(deserializeEvent(arr.getJSONObject(i)))
        }
        val sysfs = mutableListOf<LiveSysfsTransition>()
        chainObj.optJSONArray("sysfsTransitions")?.let { arr ->
            for (i in 0 until arr.length()) sysfs.add(deserializeSysfs(arr.getJSONObject(i)))
        }
        val halProcs = mutableListOf<LiveHalProcessSnapshot>()
        chainObj.optJSONArray("halProcesses")?.let { arr ->
            for (i in 0 until arr.length()) halProcs.add(deserializeHalProc(arr.getJSONObject(i)))
        }
        val extracted = mutableListOf<LiveExtractedFileRecord>()
        chainObj.optJSONArray("extractedFiles")?.let { arr ->
            for (i in 0 until arr.length()) extracted.add(deserializeExtractedFile(arr.getJSONObject(i)))
        }
        val patches = mutableListOf<LiveGeneratedPatch>()
        chainObj.optJSONArray("patches")?.let { arr ->
            for (i in 0 until arr.length()) patches.add(deserializePatch(arr.getJSONObject(i)))
        }
        val delta = chainObj.optString("beforeAfterDeltaSummary")
        val reportMd = File(dir, "00_MECANISME_FOD_DETECTE.md").takeIf { it.exists() }?.readText().orEmpty()

        LiveFodSession(
            metadata = meta,
            mechanism = mechanism,
            timelineEvents = events,
            sysfsTransitions = sysfs,
            halProcesses = halProcs,
            extractedFiles = extracted,
            patches = patches,
            rawFilesManifest = rawMap,
            beforeAfterDeltaSummary = delta,
            reportMarkdown = reportMd
        )
    }.getOrNull()

    private fun findLiveManifestDir(root: File): File? {
        if (File(root, "manifest_live_fod.json").exists()) return root
        root.listFiles()?.forEach { child ->
            if (child.isDirectory) {
                val found = findLiveManifestDir(child)
                if (found != null) return found
            }
        }
        return null
    }

    private fun zipFolderRecursive(folder: File, baseName: String, zos: ZipOutputStream) {
        val files = folder.listFiles() ?: return
        for (file in files) {
            val entryName = "$baseName/${file.name}"
            if (file.isDirectory) {
                zos.putNextEntry(ZipEntry("$entryName/"))
                zos.closeEntry()
                zipFolderRecursive(file, entryName, zos)
            } else {
                zos.putNextEntry(ZipEntry(entryName))
                FileInputStream(file).use { fis -> fis.copyTo(zos) }
                zos.closeEntry()
            }
        }
    }

    private fun serializeMetadata(m: LiveSessionMetadata): JSONObject = JSONObject()
        .put("id", m.id)
        .put("displayName", m.displayName)
        .put("romType", m.romType.name)
        .put("isImported", m.isImported)
        .put("deviceModel", m.deviceModel)
        .put("androidVersion", m.androidVersion)
        .put("sdkInt", m.sdkInt)
        .put("buildFingerprint", m.buildFingerprint)
        .put("vendorFingerprint", m.vendorFingerprint)
        .put("isDsuActive", m.isDsuActive)
        .put("rootGranted", m.rootGranted)
        .put("rootProvider", m.rootProvider)
        .put("startedAtIso", m.startedAtIso)
        .put("durationSec", m.durationSec)
        .put("sessionDirPath", m.sessionDirPath)
        .put("zipExportPath", m.zipExportPath)
        .put("totalRawLogLines", m.totalRawLogLines)
        .put("totalTimelineEvents", m.totalTimelineEvents)
        .put("extractedFilesCount", m.extractedFilesCount)
        .put("reconstructedSourcesCount", m.reconstructedSourcesCount)
        .put("patchesCount", m.patchesCount)
        .put("detectedVerdict", m.detectedVerdict)

    private fun deserializeMetadata(o: JSONObject, dirPath: String): LiveSessionMetadata = LiveSessionMetadata(
        id = o.getString("id"),
        displayName = o.optString("displayName", o.getString("id")),
        romType = runCatching { RomEnvironmentType.valueOf(o.getString("romType")) }.getOrDefault(RomEnvironmentType.INDETERMINE),
        isImported = o.optBoolean("isImported", false),
        deviceModel = o.optString("deviceModel", "Inconnu"),
        androidVersion = o.optString("androidVersion", "?"),
        sdkInt = o.optInt("sdkInt", 0),
        buildFingerprint = o.optString("buildFingerprint", ""),
        vendorFingerprint = o.optString("vendorFingerprint", ""),
        isDsuActive = o.optBoolean("isDsuActive", false),
        rootGranted = o.optBoolean("rootGranted", false),
        rootProvider = o.optString("rootProvider", ""),
        startedAtIso = o.optString("startedAtIso", ""),
        durationSec = o.optLong("durationSec", 0L),
        sessionDirPath = dirPath,
        zipExportPath = o.optString("zipExportPath").takeIf { it.isNotBlank() && it != "null" },
        totalRawLogLines = o.optInt("totalRawLogLines", 0),
        totalTimelineEvents = o.optInt("totalTimelineEvents", 0),
        extractedFilesCount = o.optInt("extractedFilesCount", 0),
        reconstructedSourcesCount = o.optInt("reconstructedSourcesCount", 0),
        patchesCount = o.optInt("patchesCount", 0),
        detectedVerdict = o.optString("detectedVerdict", "Inconnu")
    )

    private fun serializeMechanism(m: LiveDiscoveredMechanism): JSONObject = JSONObject()
        .put("primaryArchitecture", m.primaryArchitecture)
        .put("enrollmentVerdict", m.enrollmentVerdict)
        .put("explanationFr", m.explanationFr)
        .put("displayIlluminationMethod", m.displayIlluminationMethod)
        .put("touchInteractionMethod", m.touchInteractionMethod)
        .put("binderAndHalDaemons", JSONArray(m.binderAndHalDaemons))
        .put("activePackagesInChain", JSONArray(m.activePackagesInChain))
        .put("errorSignatures", JSONArray(m.errorSignatures))
        .put("hops", JSONArray().apply {
            m.hops.forEach { h ->
                put(
                    JSONObject()
                        .put("order", h.order)
                        .put("hopName", h.hopName)
                        .put("layerTag", h.layerTag)
                        .put("actorsObserved", JSONArray(h.actorsObserved))
                        .put("filesAndNodesInvolved", JSONArray(h.filesAndNodesInvolved))
                        .put("outcome", h.outcome.name)
                        .put("factualEvidence", h.factualEvidence)
                )
            }
        })

    private fun deserializeMechanism(o: JSONObject?): LiveDiscoveredMechanism {
        if (o == null) {
            return LiveDiscoveredMechanism(
                primaryArchitecture = "Inconnu",
                enrollmentVerdict = "Inconnu",
                explanationFr = "",
                displayIlluminationMethod = "Non déterminé",
                touchInteractionMethod = "Non déterminé",
                binderAndHalDaemons = emptyList(),
                activePackagesInChain = emptyList(),
                errorSignatures = emptyList(),
                hops = emptyList()
            )
        }
        val hops = mutableListOf<LiveCallChainHop>()
        o.optJSONArray("hops")?.let { arr ->
            for (i in 0 until arr.length()) {
                val h = arr.getJSONObject(i)
                hops.add(
                    LiveCallChainHop(
                        order = h.optInt("order", i + 1),
                        hopName = h.optString("hopName"),
                        layerTag = h.optString("layerTag"),
                        actorsObserved = jsonArrToList(h.optJSONArray("actorsObserved")),
                        filesAndNodesInvolved = jsonArrToList(h.optJSONArray("filesAndNodesInvolved")),
                        outcome = runCatching { LiveOutcome.valueOf(h.optString("outcome")) }.getOrDefault(LiveOutcome.INFO_TECHNIQUE),
                        factualEvidence = h.optString("factualEvidence")
                    )
                )
            }
        }
        return LiveDiscoveredMechanism(
            primaryArchitecture = o.optString("primaryArchitecture"),
            enrollmentVerdict = o.optString("enrollmentVerdict"),
            explanationFr = o.optString("explanationFr"),
            displayIlluminationMethod = o.optString("displayIlluminationMethod"),
            touchInteractionMethod = o.optString("touchInteractionMethod"),
            binderAndHalDaemons = jsonArrToList(o.optJSONArray("binderAndHalDaemons")),
            activePackagesInChain = jsonArrToList(o.optJSONArray("activePackagesInChain")),
            errorSignatures = jsonArrToList(o.optJSONArray("errorSignatures")),
            hops = hops
        )
    }

    private fun serializeEvent(e: LiveInteractionEvent): JSONObject = JSONObject()
        .put("id", e.id)
        .put("timestampMs", e.timestampMs)
        .put("relativeTimeLabel", e.relativeTimeLabel)
        .put("source", e.source.name)
        .put("actor", e.actor)
        .put("outcome", e.outcome.name)
        .put("summary", e.summary)
        .put("rawDetail", e.rawDetail.take(1200))

    private fun deserializeEvent(o: JSONObject): LiveInteractionEvent = LiveInteractionEvent(
        id = o.optString("id"),
        timestampMs = o.optLong("timestampMs", 0L),
        relativeTimeLabel = o.optString("relativeTimeLabel"),
        source = runCatching { LiveEventSource.valueOf(o.optString("source")) }.getOrDefault(LiveEventSource.LOGCAT_FOD),
        actor = o.optString("actor"),
        outcome = runCatching { LiveOutcome.valueOf(o.optString("outcome")) }.getOrDefault(LiveOutcome.INFO_TECHNIQUE),
        summary = o.optString("summary"),
        rawDetail = o.optString("rawDetail")
    )

    private fun serializeSysfs(s: LiveSysfsTransition): JSONObject = JSONObject()
        .put("path", s.path)
        .put("category", s.category)
        .put("beforeValue", s.beforeValue)
        .put("duringValues", JSONArray(s.duringValues))
        .put("afterValue", s.afterValue)
        .put("hasChanged", s.hasChanged)
        .put("permissions", s.permissions)
        .put("seLinuxContext", s.seLinuxContext)

    private fun deserializeSysfs(o: JSONObject): LiveSysfsTransition = LiveSysfsTransition(
        path = o.optString("path"),
        category = o.optString("category"),
        beforeValue = o.optString("beforeValue"),
        duringValues = jsonArrToList(o.optJSONArray("duringValues")),
        afterValue = o.optString("afterValue"),
        hasChanged = o.optBoolean("hasChanged", false),
        permissions = o.optString("permissions"),
        seLinuxContext = o.optString("seLinuxContext")
    )

    private fun serializeHalProc(h: LiveHalProcessSnapshot): JSONObject = JSONObject()
        .put("pid", h.pid)
        .put("processName", h.processName)
        .put("uid", h.uid)
        .put("seLinuxContext", h.seLinuxContext)
        .put("cmdline", h.cmdline)
        .put("openFds", JSONArray(h.openFds))
        .put("mappedFiles", JSONArray(h.mappedFiles))
        .put("unixSockets", JSONArray(h.unixSockets))
        .put("straceHighlights", JSONArray(h.straceHighlights))

    private fun deserializeHalProc(o: JSONObject): LiveHalProcessSnapshot = LiveHalProcessSnapshot(
        pid = o.optString("pid"),
        processName = o.optString("processName"),
        uid = o.optString("uid"),
        seLinuxContext = o.optString("seLinuxContext"),
        cmdline = o.optString("cmdline"),
        openFds = jsonArrToList(o.optJSONArray("openFds")),
        mappedFiles = jsonArrToList(o.optJSONArray("mappedFiles")),
        unixSockets = jsonArrToList(o.optJSONArray("unixSockets")),
        straceHighlights = jsonArrToList(o.optJSONArray("straceHighlights"))
    )

    private fun serializeExtractedFile(f: LiveExtractedFileRecord): JSONObject = JSONObject()
        .put("id", f.id)
        .put("category", f.category)
        .put("originalPath", f.originalPath)
        .put("extractedRelPath", f.extractedRelPath)
        .put("sourceCodeRelPath", f.sourceCodeRelPath)
        .put("sha256", f.sha256)
        .put("sizeBytes", f.sizeBytes)
        .put("kind", f.kind)
        .put("reasonInChain", f.reasonInChain)
        .put("rawPreview", f.rawPreview.take(4000))
        .put("reconstructedSourceCode", f.reconstructedSourceCode.take(24_000))

    private fun deserializeExtractedFile(o: JSONObject): LiveExtractedFileRecord = LiveExtractedFileRecord(
        id = o.optString("id"),
        category = o.optString("category"),
        originalPath = o.optString("originalPath"),
        extractedRelPath = o.optString("extractedRelPath").takeIf { it.isNotBlank() && it != "null" },
        sourceCodeRelPath = o.optString("sourceCodeRelPath").takeIf { it.isNotBlank() && it != "null" },
        sha256 = o.optString("sha256"),
        sizeBytes = o.optLong("sizeBytes", 0L),
        kind = o.optString("kind"),
        reasonInChain = o.optString("reasonInChain"),
        rawPreview = o.optString("rawPreview"),
        reconstructedSourceCode = o.optString("reconstructedSourceCode")
    )

    private fun serializePatch(p: LiveGeneratedPatch): JSONObject = JSONObject()
        .put("id", p.id)
        .put("fileName", p.fileName)
        .put("title", p.title)
        .put("kind", p.kind)
        .put("targetPathHint", p.targetPathHint)
        .put("description", p.description)
        .put("codeContent", p.codeContent)

    private fun deserializePatch(o: JSONObject): LiveGeneratedPatch = LiveGeneratedPatch(
        id = o.optString("id"),
        fileName = o.optString("fileName"),
        title = o.optString("title"),
        kind = o.optString("kind"),
        targetPathHint = o.optString("targetPathHint"),
        description = o.optString("description"),
        codeContent = o.optString("codeContent")
    )

    private fun jsonArrToList(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        val list = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) list.add(arr.optString(i))
        return list
    }
}

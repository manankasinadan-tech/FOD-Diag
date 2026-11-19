package com.example.core

import android.content.Context
import android.net.Uri
import android.os.Environment
import com.example.model.ComparisonReport
import com.example.model.DeviceTreeNode
import com.example.model.DexRroAnalysis
import com.example.model.DiscoveredArtifact
import com.example.model.ElfAnalysis
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
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class FodDatabaseManager(
    private val context: Context,
    private val shell: RootShellExecutor = RootShellExecutor()
) {

    fun getPreferredDatabaseDir(): File {
        val sdcardDir = File("/sdcard/FOD Database")
        val extDir = File(Environment.getExternalStorageDirectory(), "FOD Database")
        return if (sdcardDir.exists() || extDir.parentFile?.canWrite() == true) {
            extDir
        } else {
            sdcardDir
        }
    }

    fun getActiveDatabaseDir(): File {
        val primary = getPreferredDatabaseDir()
        if (ensureWritableDir(primary)) {
            return primary
        }
        val fallback = File(context.filesDir, "FOD Database")
        fallback.mkdirs()
        return fallback
    }

    fun isPrimarySdcardWritable(): Boolean {
        return ensureWritableDir(getPreferredDatabaseDir())
    }

    private fun ensureWritableDir(dir: File): Boolean {
        return runCatching {
            if (!dir.exists()) dir.mkdirs()
            if (!dir.isDirectory) return@runCatching false
            val probe = File(dir, ".fod_write_probe")
            probe.writeText("ok")
            probe.delete()
            true
        }.getOrDefault(false)
    }

    suspend fun saveSnapshot(snapshot: FodSnapshot): FodSnapshot = withContext(Dispatchers.IO) {
        val dbRoot = getActiveDatabaseDir()
        val snapDir = File(dbRoot, snapshot.metadata.id)
        val rawDir = File(snapDir, "extraction_brute")
        snapDir.mkdirs()
        rawDir.mkdirs()

        val updatedMeta = snapshot.metadata.copy(snapshotDirPath = snapDir.absolutePath)
        val updatedSnapshot = snapshot.copy(metadata = updatedMeta)

        // 1. manifest_snapshot.json
        File(snapDir, "manifest_snapshot.json").writeText(serializeMetadata(updatedMeta).toString(2))

        // 2. inventaire_sha256.json
        val artArr = JSONArray()
        updatedSnapshot.artifacts.forEach { artArr.put(serializeArtifact(it)) }
        File(snapDir, "inventaire_sha256.json").writeText(
            JSONObject().put("artefacts", artArr).toString(2)
        )

        // 3. cartographie_fod.json
        val nodesArr = JSONArray()
        updatedSnapshot.nodes.forEach { n ->
            nodesArr.put(
                JSONObject()
                    .put("id", n.id)
                    .put("label", n.label)
                    .put("layer", n.layer.name)
                    .put("status", n.status.name)
                    .put("details", n.details)
                    .put("artifactPath", n.artifactPath)
            )
        }
        val edgesArr = JSONArray()
        updatedSnapshot.edges.forEach { e ->
            edgesArr.put(
                JSONObject()
                    .put("fromId", e.fromId)
                    .put("toId", e.toId)
                    .put("relation", e.relation)
                    .put("isBroken", e.isBroken)
                    .put("evidence", e.evidence)
            )
        }
        File(snapDir, "cartographie_fod.json").writeText(
            JSONObject().put("noeuds", nodesArr).put("liens", edgesArr).toString(2)
        )

        // 4. anomalies_et_diagnostics.json
        val anomArr = JSONArray()
        updatedSnapshot.anomalies.forEach { a ->
            anomArr.put(
                JSONObject()
                    .put("id", a.id)
                    .put("title", a.title)
                    .put("severity", a.severity.name)
                    .put("layer", a.layer.name)
                    .put("evidence", a.evidence)
                    .put("impact", a.impact)
                    .put("portingAction", a.portingAction)
            )
        }
        val seArr = JSONArray()
        updatedSnapshot.selinuxFindings.forEach { s ->
            seArr.put(
                JSONObject()
                    .put("sourceType", s.sourceType)
                    .put("rawLine", s.rawLine)
                    .put("domain", s.domain)
                    .put("targetType", s.targetType)
                    .put("tclass", s.tclass)
                    .put("permission", s.permission)
            )
        }
        val propsObj = JSONObject()
        updatedSnapshot.properties.forEach { (k, v) -> propsObj.put(k, v) }
        val exclArr = JSONArray(updatedSnapshot.biometricExclusions)
        val logsArr = JSONArray(updatedSnapshot.phaseLogs)
        val areaArr = JSONArray()
        updatedSnapshot.protectedAreaAudits.forEach { a ->
            areaArr.put(
                JSONObject()
                    .put("path", a.path)
                    .put("category", a.category)
                    .put("exists", a.exists)
                    .put("permissions", a.permissions)
                    .put("ownerGroup", a.ownerGroup)
                    .put("seLinuxContext", a.seLinuxContext)
                    .put("entryCount", a.entryCount)
                    .put("note", a.note)
            )
        }

        File(snapDir, "anomalies_et_diagnostics.json").writeText(
            JSONObject()
                .put("anomalies", anomArr)
                .put("selinux", seArr)
                .put("proprietes", propsObj)
                .put("exclusions_biometriques", exclArr)
                .put("journaux_phases", logsArr)
                .put("audit_zones_protegees", areaArr)
                .toString(2)
        )

        // 5. extraction_brute/*.txt
        updatedSnapshot.liveDumps.forEach { (name, content) ->
            val safeName = name.replace(Regex("[^A-Za-z0-9_.-]"), "_")
            File(rawDir, "$safeName.txt").writeText(content)
        }

        // 6. fichiers_extraits/ (extraction réelle des libs .so, dépendances, configs, RRO)
        val extractedRoot = File(snapDir, "fichiers_extraits").apply { mkdirs() }
        var extractedTotalBytes = 0L
        val maxTotalExtractBytes = 220L * 1024L * 1024L
        for (art in updatedSnapshot.artifacts) {
            val rel = art.extractedRelativePath ?: continue
            if (BiometricPrivacyGuard.isProtectedBiometricPath(art.path)) continue
            if (extractedTotalBytes >= maxTotalExtractBytes) break
            val cleanRel = rel.removePrefix("fichiers_extraits/").trimStart('/')
            if (cleanRel.isBlank() || cleanRel.contains("..")) continue
            val destFile = File(extractedRoot, cleanRel)
            val ok = shell.copyFileToDestinationSafe(art.path, destFile, maxBytes = 24L * 1024L * 1024L)
            if (ok && destFile.exists()) {
                extractedTotalBytes += destFile.length()
            }
        }

        // 7. quasi_code_source/ (C/C++, Java DEX, XML RRO, DTSI, init.rc, SELinux .te)
        val initRcAggregate = StringBuilder()
        for (art in updatedSnapshot.artifacts) {
            art.elfAnalysis?.pseudoSourceCode?.takeIf { it.isNotBlank() }?.let { cpp ->
                val rel = art.pseudoSourcePath ?: "quasi_code_source/elf/${art.id}.cpp"
                writeSafeRelativeText(snapDir, rel, cpp)
            }
            art.dexRroAnalysis?.let { dr ->
                if (dr.pseudoSourceCode.isNotBlank()) {
                    val javaRel = if (art.pseudoSourcePath?.endsWith(".java") == true) {
                        art.pseudoSourcePath
                    } else {
                        "quasi_code_source/dex_java/${sanitizeFileSegment(art.path)}.java"
                    }
                    writeSafeRelativeText(snapDir, javaRel, dr.pseudoSourceCode)
                }
                if (dr.decodedRroXml.isNotBlank()) {
                    val xmlRel = "quasi_code_source/rro_xml/${sanitizeFileSegment(art.path)}.xml"
                    writeSafeRelativeText(snapDir, xmlRel, dr.decodedRroXml)
                }
            }
            art.deviceTreeNode?.pseudoDtsi?.takeIf { it.isNotBlank() }?.let { dtsi ->
                val rel = art.pseudoSourcePath ?: "quasi_code_source/devicetree/${sanitizeFileSegment(art.path)}.dtsi"
                writeSafeRelativeText(snapDir, rel, dtsi)
            }
            if (art.elfAnalysis == null && art.dexRroAnalysis == null && art.deviceTreeNode == null && art.rawExcerpt.isNotBlank()) {
                art.pseudoSourcePath?.let { rel ->
                    writeSafeRelativeText(snapDir, rel, "# Source: ${art.path}\n${art.rawExcerpt}")
                }
                if (art.path.endsWith(".rc")) {
                    initRcAggregate.appendLine("# === ${art.path} ===")
                    initRcAggregate.appendLine(art.rawExcerpt)
                    initRcAggregate.appendLine()
                }
            }
        }
        if (initRcAggregate.isNotBlank()) {
            writeSafeRelativeText(snapDir, "quasi_code_source/init_fod_services.rc", initRcAggregate.toString())
        }
        updatedSnapshot.liveDumps["sepolicy_fod_rules_te"]?.takeIf { it.isNotBlank() }?.let { te ->
            writeSafeRelativeText(snapDir, "quasi_code_source/fod_sepolicy.te", te)
        }

        // 8. RAPPORT_COMPLET_FOD.md
        File(snapDir, "RAPPORT_COMPLET_FOD.md").writeText(updatedSnapshot.reportMarkdown)

        updatedSnapshot
    }

    private fun writeSafeRelativeText(snapDir: File, relativePath: String, content: String) {
        val clean = relativePath.trimStart('/')
        if (clean.contains("..")) return
        runCatching {
            val target = File(snapDir, clean)
            target.parentFile?.mkdirs()
            target.writeText(content)
        }
    }

    private fun sanitizeFileSegment(path: String): String {
        return path.removePrefix("/")
            .replace('/', '_')
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(110)
    }

    suspend fun listAllSnapshots(): List<FodSnapshot> = withContext(Dispatchers.IO) {
        val roots = listOf(getPreferredDatabaseDir(), File(context.filesDir, "FOD Database"))
            .distinctBy { it.absolutePath }
        val seenIds = HashSet<String>()
        val snapshots = mutableListOf<FodSnapshot>()

        for (root in roots) {
            if (!root.exists() || !root.isDirectory) continue
            val candidates = root.listFiles()?.filter { it.isDirectory } ?: continue
            for (dir in candidates) {
                val manifest = File(dir, "manifest_snapshot.json")
                val nestedManifest = dir.listFiles()?.firstOrNull {
                    it.isDirectory && File(it, "manifest_snapshot.json").exists()
                }
                val targetDir = when {
                    manifest.exists() -> dir
                    nestedManifest != null -> nestedManifest
                    else -> null
                } ?: continue

                val snap = loadSnapshotFromDir(targetDir)
                if (snap != null && seenIds.add(snap.metadata.id)) {
                    snapshots.add(snap)
                }
            }
        }
        snapshots.sortedByDescending { it.metadata.timestampIso }
    }

    suspend fun exportSnapshotToZip(snapshot: FodSnapshot): File = withContext(Dispatchers.IO) {
        val dbRoot = getActiveDatabaseDir()
        val exportsDir = File(dbRoot, "Exports").apply { mkdirs() }
        val sourceDir = File(snapshot.metadata.snapshotDirPath)
        val ensuredSource = if (sourceDir.exists()) sourceDir else {
            saveSnapshot(snapshot)
            File(dbRoot, snapshot.metadata.id)
        }

        val zipFile = File(exportsDir, "${snapshot.metadata.id}.zip")
        ZipOutputStream(BufferedOutputStream(FileOutputStream(zipFile))).use { zos ->
            zipFolderRecursive(ensuredSource, ensuredSource.name, zos)
        }

        // Mettre à jour le chemin zip dans le manifeste
        val updatedMeta = snapshot.metadata.copy(zipExportPath = zipFile.absolutePath)
        File(ensuredSource, "manifest_snapshot.json").writeText(serializeMetadata(updatedMeta).toString(2))
        zipFile
    }

    suspend fun exportComparisonPackageToZip(
        report: ComparisonReport,
        snapA: FodSnapshot,
        snapB: FodSnapshot
    ): File = withContext(Dispatchers.IO) {
        val dbRoot = getActiveDatabaseDir()
        val exportsDir = File(dbRoot, "Exports").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val folderName = "PLAN_PORTAGE_FOD_$stamp"
        val stagingDir = File(exportsDir, folderName).apply { mkdirs() }

        try {
            // 1. Rapports Markdown & Plan d'implémentation
            File(stagingDir, "RAPPORT_COMPARAISON_COMPLET.md").writeText(report.reportMarkdown)
            File(stagingDir, "PLAN_IMPLEMENTATION_FOD.md").writeText(
                report.implementationPlanMarkdown.ifBlank { report.reportMarkdown }
            )

            // 2. comparison_data.json
            val verdictsArr = JSONArray()
            report.layerVerdicts.forEach { v ->
                verdictsArr.put(
                    JSONObject()
                        .put("id", v.id)
                        .put("layer", v.layer.name)
                        .put("title", v.title)
                        .put("statusInA", v.statusInA)
                        .put("statusInB", v.statusInB)
                        .put("isBlocking", v.isBlocking)
                        .put("rootCause", v.rootCause)
                        .put("evidenceA", v.evidenceA)
                        .put("evidenceB", v.evidenceB)
                        .put("imitationSolution", v.imitationSolution)
                )
            }
            val patchesArr = JSONArray()
            report.generatedPatches.forEach { p ->
                patchesArr.put(
                    JSONObject()
                        .put("id", p.id)
                        .put("fileName", p.fileName)
                        .put("title", p.title)
                        .put("kind", p.kind)
                        .put("targetPathHint", p.targetPathHint)
                        .put("description", p.description)
                        .put("codeContent", p.codeContent)
                )
            }
            val diffsArr = JSONArray()
            report.diffs.forEach { d ->
                diffsArr.put(
                    JSONObject()
                        .put("id", d.id)
                        .put("category", d.category.name)
                        .put("layer", d.layer.name)
                        .put("severity", d.severity.name)
                        .put("keyOrPath", d.keyOrPath)
                        .put("valueA", d.valueA)
                        .put("valueB", d.valueB)
                        .put("portingNote", d.portingNote)
                )
            }
            File(stagingDir, "comparison_data.json").writeText(
                JSONObject()
                    .put("snapshotA", serializeMetadata(report.snapshotA))
                    .put("snapshotB", serializeMetadata(report.snapshotB))
                    .put("criticalBlockersCount", report.criticalBlockersCount)
                    .put("missingInBCount", report.missingInBCount)
                    .put("modifiedShaCount", report.modifiedShaCount)
                    .put("propertyDeltaCount", report.propertyDeltaCount)
                    .put("deepFindingsCount", report.deepFindingsCount)
                    .put("gsiFailureSummary", report.gsiFailureSummary)
                    .put("portingChecklistFr", JSONArray(report.portingChecklistFr))
                    .put("layerVerdicts", verdictsArr)
                    .put("generatedPatches", patchesArr)
                    .put("diffs", diffsArr)
                    .toString(2)
            )

            // 3. patchs_proposes/*
            val patchDir = File(stagingDir, "patchs_proposes").apply { mkdirs() }
            report.generatedPatches.forEach { p ->
                val cleanName = p.fileName.replace(Regex("[^A-Za-z0-9._-]"), "_")
                if (cleanName.isNotBlank()) {
                    File(patchDir, cleanName).writeText(p.codeContent)
                }
            }

            // 4. fichiers_a_porter_de_A/ et quasi_code_source_A/ (uniquement non-sensibles manquants/divergents)
            val snapADir = File(snapA.metadata.snapshotDirPath)
            val mapB = snapB.artifacts.associateBy { it.path }
            val portFilesDir = File(stagingDir, "fichiers_a_porter_de_A").apply { mkdirs() }
            val portPseudoDir = File(stagingDir, "quasi_code_source_A").apply { mkdirs() }
            var copiedBytes = 0L
            val maxCopyBytes = 120L * 1024L * 1024L

            for (artA in snapA.artifacts) {
                if (BiometricPrivacyGuard.isProtectedBiometricPath(artA.path)) continue
                val artB = mapB[artA.path]
                val needsPort = artB == null || (artA.sha256 != artB.sha256 && artA.sha256 != "INDISPONIBLE")
                if (!needsPort) continue

                artA.extractedRelativePath?.let { rel ->
                    if (copiedBytes < maxCopyBytes) {
                        val src = File(snapADir, rel)
                        if (src.exists() && src.isFile) {
                            val cleanRel = rel.removePrefix("fichiers_extraits/").trimStart('/')
                            if (!cleanRel.contains("..")) {
                                val dst = File(portFilesDir, cleanRel)
                                dst.parentFile?.mkdirs()
                                src.copyTo(dst, overwrite = true)
                                copiedBytes += dst.length()
                            }
                        }
                    }
                }
                artA.pseudoSourcePath?.let { rel ->
                    val src = File(snapADir, rel)
                    if (src.exists() && src.isFile) {
                        val cleanRel = rel.removePrefix("quasi_code_source/").trimStart('/')
                        if (!cleanRel.contains("..")) {
                            val dst = File(portPseudoDir, cleanRel)
                            dst.parentFile?.mkdirs()
                            src.copyTo(dst, overwrite = true)
                        }
                    }
                }
            }

            val zipFile = File(exportsDir, "COMPARAISON_FOD_${stamp}.zip")
            ZipOutputStream(BufferedOutputStream(FileOutputStream(zipFile))).use { zos ->
                zipFolderRecursive(stagingDir, stagingDir.name, zos)
            }
            zipFile
        } finally {
            stagingDir.deleteRecursively()
        }
    }

    suspend fun importZipFromUri(uri: Uri): Result<FodSnapshot> = withContext(Dispatchers.IO) {
        runCatching {
            val dbRoot = getActiveDatabaseDir()
            val stagingName = "IMPORT_${System.currentTimeMillis()}"
            val stagingDir = File(dbRoot, stagingName).apply { mkdirs() }

            val inputStream = context.contentResolver.openInputStream(uri)
                ?: throw IllegalStateException("Impossible d'ouvrir le fichier .zip sélectionné.")

            var entryCount = 0
            ZipInputStream(BufferedInputStream(inputStream)).use { zis ->
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
                        FileOutputStream(outFile).use { fos ->
                            zis.copyTo(fos)
                        }
                        entryCount++
                    }
                    zis.closeEntry()
                }
            }

            if (entryCount == 0) {
                stagingDir.deleteRecursively()
                throw IllegalArgumentException("L'archive .zip sélectionnée est vide.")
            }

            // Localiser le dossier contenant manifest_snapshot.json (racine ou sous-dossier)
            val snapDir = findManifestDir(stagingDir)
                ?: throw IllegalArgumentException(
                    "Archive décompressée dans ${stagingDir.absolutePath}, mais aucun manifest_snapshot.json FOD Lab détecté."
                )

            // Si le snapshot était dans un sous-dossier unique, le remonter proprement si possible
            val finalDir = if (snapDir != stagingDir) {
                val targetName = snapDir.name.ifBlank { stagingName }
                val dest = File(dbRoot, "${targetName}_imp_${System.currentTimeMillis() % 10000}")
                if (snapDir.renameTo(dest)) {
                    stagingDir.deleteRecursively()
                    dest
                } else {
                    snapDir
                }
            } else {
                stagingDir
            }

            val loaded = loadSnapshotFromDir(finalDir)
                ?: throw IllegalStateException("Impossible de lire les données de la capture importée.")

            val importedId = if (loaded.metadata.isImported) loaded.metadata.id else "${loaded.metadata.id}_imp"
            val updatedMeta = loaded.metadata.copy(
                id = importedId,
                isImported = true,
                displayName = if (loaded.metadata.displayName.contains("[Importé]")) {
                    loaded.metadata.displayName
                } else {
                    "[Importé] ${loaded.metadata.displayName}"
                },
                snapshotDirPath = finalDir.absolutePath
            )
            File(finalDir, "manifest_snapshot.json").writeText(serializeMetadata(updatedMeta).toString(2))
            loaded.copy(metadata = updatedMeta)
        }
    }

    suspend fun deleteSnapshot(snapshot: FodSnapshot): Boolean = withContext(Dispatchers.IO) {
        val dir = File(snapshot.metadata.snapshotDirPath)
        if (dir.exists()) dir.deleteRecursively() else false
    }

    private fun findManifestDir(root: File): File? {
        if (File(root, "manifest_snapshot.json").exists()) return root
        root.listFiles()?.forEach { child ->
            if (child.isDirectory) {
                val found = findManifestDir(child)
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

    private fun loadSnapshotFromDir(dir: File): FodSnapshot? = runCatching {
        val metaJson = JSONObject(File(dir, "manifest_snapshot.json").readText())
        val meta = deserializeMetadata(metaJson, dir.absolutePath)

        val artifacts = mutableListOf<DiscoveredArtifact>()
        val invFile = File(dir, "inventaire_sha256.json")
        if (invFile.exists()) {
            val arr = JSONObject(invFile.readText()).optJSONArray("artefacts") ?: JSONArray()
            for (i in 0 until arr.length()) {
                artifacts.add(deserializeArtifact(arr.getJSONObject(i)))
            }
        }

        val nodes = mutableListOf<FodNode>()
        val edges = mutableListOf<FodEdge>()
        val mapFile = File(dir, "cartographie_fod.json")
        if (mapFile.exists()) {
            val obj = JSONObject(mapFile.readText())
            val nArr = obj.optJSONArray("noeuds") ?: JSONArray()
            for (i in 0 until nArr.length()) {
                val n = nArr.getJSONObject(i)
                nodes.add(
                    FodNode(
                        id = n.getString("id"),
                        label = n.getString("label"),
                        layer = SystemLayer.valueOf(n.getString("layer")),
                        status = NodeStatus.valueOf(n.getString("status")),
                        details = n.optString("details"),
                        artifactPath = n.optString("artifactPath").takeIf { it.isNotBlank() && it != "null" }
                    )
                )
            }
            val eArr = obj.optJSONArray("liens") ?: JSONArray()
            for (i in 0 until eArr.length()) {
                val e = eArr.getJSONObject(i)
                edges.add(
                    FodEdge(
                        fromId = e.getString("fromId"),
                        toId = e.getString("toId"),
                        relation = e.getString("relation"),
                        isBroken = e.optBoolean("isBroken", false),
                        evidence = e.optString("evidence")
                    )
                )
            }
        }

        val anomalies = mutableListOf<FodAnomaly>()
        val selinux = mutableListOf<SelinuxFinding>()
        val props = LinkedHashMap<String, String>()
        val exclusions = mutableListOf<String>()
        val phaseLogs = mutableListOf<String>()
        val protectedAudits = mutableListOf<ProtectedAreaMetadata>()

        val diagFile = File(dir, "anomalies_et_diagnostics.json")
        if (diagFile.exists()) {
            val obj = JSONObject(diagFile.readText())
            val aArr = obj.optJSONArray("anomalies") ?: JSONArray()
            for (i in 0 until aArr.length()) {
                val a = aArr.getJSONObject(i)
                anomalies.add(
                    FodAnomaly(
                        id = a.getString("id"),
                        title = a.getString("title"),
                        severity = SeverityLevel.valueOf(a.getString("severity")),
                        layer = SystemLayer.valueOf(a.getString("layer")),
                        evidence = a.optString("evidence"),
                        impact = a.optString("impact"),
                        portingAction = a.optString("portingAction")
                    )
                )
            }
            val sArr = obj.optJSONArray("selinux") ?: JSONArray()
            for (i in 0 until sArr.length()) {
                val s = sArr.getJSONObject(i)
                selinux.add(
                    SelinuxFinding(
                        sourceType = s.optString("sourceType"),
                        rawLine = s.optString("rawLine"),
                        domain = s.optString("domain").takeIf { it.isNotBlank() && it != "null" },
                        targetType = s.optString("targetType").takeIf { it.isNotBlank() && it != "null" },
                        tclass = s.optString("tclass").takeIf { it.isNotBlank() && it != "null" },
                        permission = s.optString("permission").takeIf { it.isNotBlank() && it != "null" }
                    )
                )
            }
            val pObj = obj.optJSONObject("proprietes")
            pObj?.keys()?.forEach { key -> props[key] = pObj.optString(key) }
            val exArr = obj.optJSONArray("exclusions_biometriques") ?: JSONArray()
            for (i in 0 until exArr.length()) exclusions.add(exArr.getString(i))
            val lArr = obj.optJSONArray("journaux_phases") ?: JSONArray()
            for (i in 0 until lArr.length()) phaseLogs.add(lArr.getString(i))
            val areaArr = obj.optJSONArray("audit_zones_protegees") ?: JSONArray()
            for (i in 0 until areaArr.length()) {
                val ar = areaArr.getJSONObject(i)
                protectedAudits.add(
                    ProtectedAreaMetadata(
                        path = ar.optString("path"),
                        category = ar.optString("category"),
                        exists = ar.optBoolean("exists", false),
                        permissions = ar.optString("permissions", "-"),
                        ownerGroup = ar.optString("ownerGroup", "-"),
                        seLinuxContext = ar.optString("seLinuxContext", "-"),
                        entryCount = ar.optInt("entryCount", 0),
                        note = ar.optString("note")
                    )
                )
            }
        }

        val liveDumps = LinkedHashMap<String, String>()
        val rawDir = File(dir, "extraction_brute")
        if (rawDir.exists() && rawDir.isDirectory) {
            rawDir.listFiles()?.forEach { f ->
                if (f.isFile && f.name.endsWith(".txt")) {
                    liveDumps[f.name.removeSuffix(".txt")] = f.readText()
                }
            }
        }

        val reportMd = File(dir, "RAPPORT_COMPLET_FOD.md").takeIf { it.exists() }?.readText().orEmpty()

        FodSnapshot(
            metadata = meta,
            artifacts = artifacts,
            nodes = nodes,
            edges = edges,
            anomalies = anomalies,
            properties = props,
            liveDumps = liveDumps,
            selinuxFindings = selinux,
            biometricExclusions = exclusions,
            reportMarkdown = reportMd,
            phaseLogs = phaseLogs,
            protectedAreaAudits = protectedAudits
        )
    }.getOrNull()

    private fun serializeMetadata(m: SnapshotMetadata): JSONObject {
        return JSONObject()
            .put("id", m.id)
            .put("displayName", m.displayName)
            .put("romType", m.romType.name)
            .put("isImported", m.isImported)
            .put("deviceModel", m.deviceModel)
            .put("deviceManufacturer", m.deviceManufacturer)
            .put("deviceCodename", m.deviceCodename)
            .put("boardPlatform", m.boardPlatform)
            .put("socModel", m.socModel)
            .put("androidVersion", m.androidVersion)
            .put("sdkInt", m.sdkInt)
            .put("buildFingerprint", m.buildFingerprint)
            .put("vendorFingerprint", m.vendorFingerprint)
            .put("kernelVersion", m.kernelVersion)
            .put("seLinuxMode", m.seLinuxMode)
            .put("rootGranted", m.rootGranted)
            .put("rootProvider", m.rootProvider)
            .put("isDsuActive", m.isDsuActive)
            .put("timestampIso", m.timestampIso)
            .put("snapshotDirPath", m.snapshotDirPath)
            .put("zipExportPath", m.zipExportPath)
            .put("completenessScore", m.completenessScore)
    }

    private fun deserializeMetadata(o: JSONObject, actualDirPath: String): SnapshotMetadata {
        return SnapshotMetadata(
            id = o.getString("id"),
            displayName = o.optString("displayName", o.getString("id")),
            romType = runCatching { RomEnvironmentType.valueOf(o.getString("romType")) }.getOrDefault(RomEnvironmentType.INDETERMINE),
            isImported = o.optBoolean("isImported", false),
            deviceModel = o.optString("deviceModel", "Inconnu"),
            deviceManufacturer = o.optString("deviceManufacturer", "Inconnu"),
            deviceCodename = o.optString("deviceCodename", "Inconnu"),
            boardPlatform = o.optString("boardPlatform", "Inconnu"),
            socModel = o.optString("socModel", "Inconnu"),
            androidVersion = o.optString("androidVersion", "?"),
            sdkInt = o.optInt("sdkInt", 0),
            buildFingerprint = o.optString("buildFingerprint", "Inconnu"),
            vendorFingerprint = o.optString("vendorFingerprint", "Inconnu"),
            kernelVersion = o.optString("kernelVersion", "Inconnu"),
            seLinuxMode = o.optString("seLinuxMode", "Inconnu"),
            rootGranted = o.optBoolean("rootGranted", false),
            rootProvider = o.optString("rootProvider", "Inconnu"),
            isDsuActive = o.optBoolean("isDsuActive", false),
            timestampIso = o.optString("timestampIso", ""),
            snapshotDirPath = actualDirPath,
            zipExportPath = o.optString("zipExportPath").takeIf { it.isNotBlank() && it != "null" },
            completenessScore = o.optInt("completenessScore", 0)
        )
    }

    private fun serializeArtifact(a: DiscoveredArtifact): JSONObject {
        val obj = JSONObject()
            .put("id", a.id)
            .put("path", a.path)
            .put("layer", a.layer.name)
            .put("kind", a.kind)
            .put("sha256", a.sha256)
            .put("sizeBytes", a.sizeBytes)
            .put("permissions", a.permissions)
            .put("seLinuxContext", a.seLinuxContext)
            .put("summary", a.summary)
            .put("isOemPatch", a.isOemPatch)
            .put("rawExcerpt", a.rawExcerpt)
            .put("extractedRelativePath", a.extractedRelativePath)
            .put("pseudoSourcePath", a.pseudoSourcePath)

        a.elfAnalysis?.let { elf ->
            val resolvedObj = JSONObject()
            elf.resolvedDependencies.forEach { (k, v) -> resolvedObj.put(k, v) }
            obj.put(
                "elfAnalysis",
                JSONObject()
                    .put("machine", elf.machine)
                    .put("is64Bit", elf.is64Bit)
                    .put("soName", elf.soName)
                    .put("neededLibraries", JSONArray(elf.neededLibraries))
                    .put("resolvedDependencies", resolvedObj)
                    .put("missingLibraries", JSONArray(elf.missingLibraries))
                    .put("fodSymbols", JSONArray(elf.fodSymbols))
                    .put("exportedSymbols", JSONArray(elf.exportedSymbols))
                    .put("importedSymbols", JSONArray(elf.importedSymbols))
                    .put("fodStrings", JSONArray(elf.fodStrings))
                    .put("pseudoSourceCode", elf.pseudoSourceCode.take(32_000))
            )
        }

        a.dexRroAnalysis?.let { dr ->
            val propsObj = JSONObject()
            dr.udfpsProperties.forEach { (k, v) -> propsObj.put(k, v) }
            obj.put(
                "dexRroAnalysis",
                JSONObject()
                    .put("sourcePath", dr.sourcePath)
                    .put("packageName", dr.packageName)
                    .put("rroTargetPackage", dr.rroTargetPackage)
                    .put("rroPriority", dr.rroPriority)
                    .put("matchedClasses", JSONArray(dr.matchedClasses))
                    .put("matchedMethods", JSONArray(dr.matchedMethods))
                    .put("matchedConfigKeys", JSONArray(dr.matchedConfigKeys))
                    .put("udfpsProperties", propsObj)
                    .put("decodedRroXml", dr.decodedRroXml.take(16_000))
                    .put("pseudoSourceCode", dr.pseudoSourceCode.take(32_000))
            )
        }

        a.deviceTreeNode?.let { dt ->
            val pObj = JSONObject()
            dt.properties.forEach { (k, v) -> pObj.put(k, v) }
            obj.put(
                "deviceTreeNode",
                JSONObject()
                    .put("nodePath", dt.nodePath)
                    .put("compatible", dt.compatible)
                    .put("properties", pObj)
                    .put("pseudoDtsi", dt.pseudoDtsi.take(12_000))
            )
        }

        return obj
    }

    private fun deserializeArtifact(o: JSONObject): DiscoveredArtifact {
        val elfObj = o.optJSONObject("elfAnalysis")
        val elf = elfObj?.let {
            val resObj = it.optJSONObject("resolvedDependencies")
            val resMap = LinkedHashMap<String, String>()
            resObj?.keys()?.forEach { k -> resMap[k] = resObj.optString(k) }
            ElfAnalysis(
                machine = it.optString("machine"),
                is64Bit = it.optBoolean("is64Bit", true),
                soName = it.optString("soName").takeIf { s -> s.isNotBlank() && s != "null" },
                neededLibraries = jsonArrayToList(it.optJSONArray("neededLibraries")),
                resolvedDependencies = resMap,
                missingLibraries = jsonArrayToList(it.optJSONArray("missingLibraries")),
                fodSymbols = jsonArrayToList(it.optJSONArray("fodSymbols")),
                exportedSymbols = jsonArrayToList(it.optJSONArray("exportedSymbols")),
                importedSymbols = jsonArrayToList(it.optJSONArray("importedSymbols")),
                fodStrings = jsonArrayToList(it.optJSONArray("fodStrings")),
                pseudoSourceCode = it.optString("pseudoSourceCode")
            )
        }

        val drObj = o.optJSONObject("dexRroAnalysis")
        val dr = drObj?.let {
            val pObj = it.optJSONObject("udfpsProperties")
            val pMap = LinkedHashMap<String, String>()
            pObj?.keys()?.forEach { k -> pMap[k] = pObj.optString(k) }
            DexRroAnalysis(
                sourcePath = it.optString("sourcePath"),
                packageName = it.optString("packageName").takeIf { s -> s.isNotBlank() && s != "null" },
                rroTargetPackage = it.optString("rroTargetPackage").takeIf { s -> s.isNotBlank() && s != "null" },
                rroPriority = if (it.has("rroPriority") && !it.isNull("rroPriority")) it.optInt("rroPriority") else null,
                matchedClasses = jsonArrayToList(it.optJSONArray("matchedClasses")),
                matchedMethods = jsonArrayToList(it.optJSONArray("matchedMethods")),
                matchedConfigKeys = jsonArrayToList(it.optJSONArray("matchedConfigKeys")),
                udfpsProperties = pMap,
                decodedRroXml = it.optString("decodedRroXml"),
                pseudoSourceCode = it.optString("pseudoSourceCode")
            )
        }

        val dtObj = o.optJSONObject("deviceTreeNode")
        val dt = dtObj?.let {
            val pObj = it.optJSONObject("properties")
            val pMap = LinkedHashMap<String, String>()
            pObj?.keys()?.forEach { k -> pMap[k] = pObj.optString(k) }
            DeviceTreeNode(
                nodePath = it.optString("nodePath"),
                compatible = it.optString("compatible").takeIf { s -> s.isNotBlank() && s != "null" },
                properties = pMap,
                pseudoDtsi = it.optString("pseudoDtsi")
            )
        }

        return DiscoveredArtifact(
            id = o.getString("id"),
            path = o.getString("path"),
            layer = SystemLayer.valueOf(o.getString("layer")),
            kind = o.optString("kind"),
            sha256 = o.optString("sha256"),
            sizeBytes = o.optLong("sizeBytes", 0L),
            permissions = o.optString("permissions"),
            seLinuxContext = o.optString("seLinuxContext"),
            summary = o.optString("summary"),
            isOemPatch = o.optBoolean("isOemPatch", false),
            elfAnalysis = elf,
            dexRroAnalysis = dr,
            deviceTreeNode = dt,
            rawExcerpt = o.optString("rawExcerpt"),
            extractedRelativePath = o.optString("extractedRelativePath").takeIf { s -> s.isNotBlank() && s != "null" },
            pseudoSourcePath = o.optString("pseudoSourcePath").takeIf { s -> s.isNotBlank() && s != "null" }
        )
    }

    private fun jsonArrayToList(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        val list = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) list.add(arr.optString(i))
        return list
    }
}

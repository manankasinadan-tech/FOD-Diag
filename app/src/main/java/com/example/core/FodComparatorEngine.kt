package com.example.core

import com.example.model.ComparisonDiffItem
import com.example.model.ComparisonReport
import com.example.model.DiffCategory
import com.example.model.FodSnapshot
import com.example.model.GeneratedPatchArtifact
import com.example.model.GsiBlockerVerdict
import com.example.model.NodeStatus
import com.example.model.ProtectedAreaMetadata
import com.example.model.SeverityLevel
import com.example.model.SystemLayer

object FodComparatorEngine {

    fun compare(snapshotA: FodSnapshot, snapshotB: FodSnapshot): ComparisonReport {
        val diffs = mutableListOf<ComparisonDiffItem>()
        val checklist = LinkedHashSet<String>()

        val mapA = snapshotA.artifacts.associateBy { it.path }
        val mapB = snapshotB.artifacts.associateBy { it.path }

        // 1. Artefacts présents dans A (ex: ROM Stock), absents ou modifiés dans B (ex: GSI)
        for ((path, artA) in mapA) {
            if (!mapB.containsKey(path)) {
                val isCritical = artA.layer == SystemLayer.HAL ||
                    artA.layer == SystemLayer.VENDOR ||
                    artA.layer == SystemLayer.FRAMEWORK ||
                    artA.isOemPatch ||
                    artA.dexRroAnalysis?.rroTargetPackage != null

                val severity = if (isCritical) SeverityLevel.CRITIQUE else SeverityLevel.AVERTISSEMENT
                val note = when {
                    artA.dexRroAnalysis?.rroTargetPackage != null ->
                        "Overlay RRO ciblant ${artA.dexRroAnalysis.rroTargetPackage} absent dans B. Porter l'overlay ou ses clés resources.arsc (${artA.dexRroAnalysis.matchedConfigKeys.take(6).joinToString(", ")})."
                    artA.elfAnalysis != null ->
                        "Binaire/Lib ELF absent dans B. Dépendances DT_NEEDED requises : ${artA.elfAnalysis.neededLibraries.joinToString(", ")}."
                    artA.kind.contains("Init") ->
                        "Script init.rc absent dans B : vérifier les services HAL démarrés au boot."
                    else ->
                        "Élément présent dans ${snapshotA.metadata.romType.labelFr} mais non découvert dans ${snapshotB.metadata.romType.labelFr}."
                }

                diffs.add(
                    ComparisonDiffItem(
                        id = "diff_miss_${diffs.size}",
                        category = DiffCategory.MANQUANT_DANS_B,
                        layer = artA.layer,
                        severity = severity,
                        keyOrPath = path,
                        valueA = "${artA.kind} (SHA256: ${artA.sha256.take(12)}...)",
                        valueB = "Absent",
                        portingNote = note
                    )
                )
                if (isCritical) {
                    checklist.add("[${artA.layer.labelFr}] Vérifier/porter `$path` (${artA.summary})")
                }
            } else {
                val artB = mapB.getValue(path)
                if (artA.sha256 != artB.sha256 && artA.sha256 != "INDISPONIBLE" && artB.sha256 != "INDISPONIBLE") {
                    val elfMissDiff = (artB.elfAnalysis?.missingLibraries ?: emptyList()) - (artA.elfAnalysis?.missingLibraries ?: emptyList()).toSet()
                    val missingExports = (artA.elfAnalysis?.exportedSymbols ?: emptyList()) - (artB.elfAnalysis?.exportedSymbols ?: emptyList()).toSet()
                    val note = when {
                        elfMissDiff.isNotEmpty() ->
                            "SHA-256 différent ET nouvelles dépendances ELF manquantes dans B : ${elfMissDiff.joinToString(", ")}."
                        missingExports.isNotEmpty() ->
                            "SHA-256 différent et ${missingExports.size} symbole(s) exporté(s) dans A absent(s) dans B (ex: ${missingExports.take(4).joinToString(", ")})."
                        else ->
                            "Contenu/binaire différent entre A et B (SHA-256 modifié). Comparer les symboles/classes et clés RRO."
                    }
                    diffs.add(
                        ComparisonDiffItem(
                            id = "diff_sha_${diffs.size}",
                            category = DiffCategory.MODIFIE_SHA256,
                            layer = artA.layer,
                            severity = if (elfMissDiff.isNotEmpty()) SeverityLevel.CRITIQUE else SeverityLevel.AVERTISSEMENT,
                            keyOrPath = path,
                            valueA = "SHA256: ${artA.sha256.take(16)}… | ${artA.summary}",
                            valueB = "SHA256: ${artB.sha256.take(16)}… | ${artB.summary}",
                            portingNote = note
                        )
                    )
                    if (elfMissDiff.isNotEmpty()) {
                        checklist.add("[ELF] Résoudre les bibliothèques manquantes pour `$path` : ${elfMissDiff.joinToString(", ")}")
                    }
                }
            }
        }

        // 2. Nouveau dans B
        for ((path, artB) in mapB) {
            if (!mapA.containsKey(path)) {
                diffs.add(
                    ComparisonDiffItem(
                        id = "diff_new_${diffs.size}",
                        category = DiffCategory.NOUVEAU_DANS_B,
                        layer = artB.layer,
                        severity = SeverityLevel.INFO,
                        keyOrPath = path,
                        valueA = "Absent",
                        valueB = "${artB.kind} (SHA256: ${artB.sha256.take(12)}...)",
                        portingNote = "Élément introduit dans B (ex: implémentation générique AOSP/GSI)."
                    )
                )
            }
        }

        // 3. Propriétés système divergentes
        val allPropKeys = (snapshotA.properties.keys + snapshotB.properties.keys).sorted()
        for (key in allPropKeys) {
            val valA = snapshotA.properties[key]
            val valB = snapshotB.properties[key]
            if (valA != valB) {
                val layer = when {
                    key.contains("display") || key.contains("hbm") || key.contains("lhbm") -> SystemLayer.DISPLAY
                    key.contains("touch") -> SystemLayer.TOUCH
                    key.contains("vendor") -> SystemLayer.VENDOR
                    else -> SystemLayer.FRAMEWORK
                }
                val severity = if (valA != null && valB == null) SeverityLevel.AVERTISSEMENT else SeverityLevel.INFO
                diffs.add(
                    ComparisonDiffItem(
                        id = "diff_prop_${diffs.size}",
                        category = DiffCategory.PROPRIETE_DIVERGENTE,
                        layer = layer,
                        severity = severity,
                        keyOrPath = key,
                        valueA = valA ?: "<non défini>",
                        valueB = valB ?: "<non défini>",
                        portingNote = if (valA != null && valB == null) {
                            "Propriété définie uniquement dans A. Tester l'ajout via resetprop/overlay : $key=$valA"
                        } else {
                            "Valeur divergente entre A et B (remettre $valA dans system.prop / resetprop)."
                        }
                    )
                )
                if (valA != null && (key.contains("finger") || key.contains("udfps") || key.contains("fod") || key.contains("hbm") || key.contains("lhbm"))) {
                    checklist.add("[Propriété] Définir `$key=$valA` sur le système cible")
                }
            }
        }

        // 4. Comparaison profonde DEX / RRO (classes UDFPS & clés config absentes dans B)
        val classesA = snapshotA.artifacts.flatMap { it.dexRroAnalysis?.matchedClasses.orEmpty() }.toSet()
        val classesB = snapshotB.artifacts.flatMap { it.dexRroAnalysis?.matchedClasses.orEmpty() }.toSet()
        val missingClassesInB = (classesA - classesB)
            .filter { c ->
                val l = c.lowercase()
                l.contains("udfps") || l.contains("fod") || l.contains("hbm") || l.contains("displayfeature") || l.contains("touchfeature")
            }
            .sorted()
        if (missingClassesInB.isNotEmpty()) {
            diffs.add(
                ComparisonDiffItem(
                    id = "diff_dex_classes",
                    category = DiffCategory.HAL_SERVICE_OU_SYSTEME,
                    layer = SystemLayer.FRAMEWORK,
                    severity = SeverityLevel.CRITIQUE,
                    keyOrPath = "Classes DEX UDFPS/FOD (${missingClassesInB.size} absentes dans B)",
                    valueA = missingClassesInB.take(12).joinToString(", "),
                    valueB = "Absentes de SystemUI/framework/services dans B",
                    portingNote = "Le GSI utilise un SystemUI/Framework générique dépourvu des handlers constructeur (${missingClassesInB.take(5).joinToString(", ")}). Il faut un module/patch UDFPS/RRO pour reproduire leur logique d'illumination et de notification tactile."
                )
            )
            checklist.add("[Framework/SystemUI] Reproduire les contrôleurs UDFPS manquants (${missingClassesInB.take(4).joinToString(", ")})")
        }

        val configKeysA = snapshotA.artifacts.flatMap { it.dexRroAnalysis?.matchedConfigKeys.orEmpty() }.toSet()
        val configKeysB = snapshotB.artifacts.flatMap { it.dexRroAnalysis?.matchedConfigKeys.orEmpty() }.toSet()
        val missingConfigKeysInB = (configKeysA - configKeysB)
            .filter { k ->
                val l = k.lowercase()
                l.contains("udfps") || l.contains("fod") || l.contains("hbm") || l.contains("fingerprint")
            }
            .sorted()
        if (missingConfigKeysInB.isNotEmpty()) {
            diffs.add(
                ComparisonDiffItem(
                    id = "diff_rro_keys",
                    category = DiffCategory.HAL_SERVICE_OU_SYSTEME,
                    layer = SystemLayer.FRAMEWORK,
                    severity = SeverityLevel.CRITIQUE,
                    keyOrPath = "Clés RRO / resources.arsc (${missingConfigKeysInB.size} absentes dans B)",
                    valueA = missingConfigKeysInB.take(14).joinToString(", "),
                    valueB = "Absentes des ressources SystemUI/framework-res de B",
                    portingNote = "Porter ces clés dans un RRO overlay ciblant `com.android.systemui` ou `android` (framework-res) : ${missingConfigKeysInB.take(8).joinToString(", ")}."
                )
            )
            checklist.add("[RRO] Injecter les clés `resources.arsc` manquantes : ${missingConfigKeysInB.take(6).joinToString(", ")}")
        }

        // 5. Comparaison des interfaces HAL / Binder / Keystore / Gatekeeper / TEE enregistrées en direct
        val halLinesA = extractServiceTokens(snapshotA)
        val halLinesB = extractServiceTokens(snapshotB)
        val missingServicesInB = (halLinesA - halLinesB).sorted()
        if (missingServicesInB.isNotEmpty()) {
            diffs.add(
                ComparisonDiffItem(
                    id = "diff_hal_services",
                    category = DiffCategory.HAL_SERVICE_OU_SYSTEME,
                    layer = SystemLayer.HAL,
                    severity = SeverityLevel.CRITIQUE,
                    keyOrPath = "Interfaces HAL / Binder actives (${missingServicesInB.size} absentes dans B)",
                    valueA = missingServicesInB.take(10).joinToString("\n"),
                    valueB = "Non enregistrées dans lshal / service list de B",
                    portingNote = "Ces services HAL/AIDL/HIDL tournent dans la ROM d'origine mais pas dans le GSI. Vérifier les dépendances DT_NEEDED, le manifeste VINTF et init.*.rc."
                )
            )
            checklist.add("[HAL/Binder] Rétablir l'enregistrement de : ${missingServicesInB.take(4).joinToString(", ")}")
        }

        // 6. Comparaison des métadonnées structurelles Biométrie / Keystore / Persist / TEE (sans secrets)
        val auditMapA = snapshotA.protectedAreaAudits.associateBy { it.path }
        val auditMapB = snapshotB.protectedAreaAudits.associateBy { it.path }
        val allAuditPaths = (auditMapA.keys + auditMapB.keys).sorted()
        for (p in allAuditPaths) {
            val a = auditMapA[p]
            val b = auditMapB[p]
            if (a != null && b != null) {
                val missingInB = a.exists && !b.exists
                val ctxChanged = a.exists && b.exists && (a.seLinuxContext != b.seLinuxContext || a.ownerGroup != b.ownerGroup)
                if (missingInB || ctxChanged) {
                    val severity = if (missingInB || a.seLinuxContext != b.seLinuxContext) SeverityLevel.CRITIQUE else SeverityLevel.AVERTISSEMENT
                    diffs.add(
                        ComparisonDiffItem(
                            id = "diff_bio_meta_${diffs.size}",
                            category = DiffCategory.BIO_KEYSTORE_TEE,
                            layer = SystemLayer.SELINUX,
                            severity = severity,
                            keyOrPath = "Métadonnées zone protégée : $p",
                            valueA = formatProtectedMeta(a),
                            valueB = formatProtectedMeta(b),
                            portingNote = if (missingInB) {
                                "Le chemin existe sur la ROM d'origine (${a.ownerGroup}, ${a.seLinuxContext}) mais est absent dans B. Ajouter `mkdir $p` + `chown` + `restorecon` dans `init.rc` (aucun contenu secret copié)."
                            } else {
                                "Divergence d'ownership ou de contexte SELinux sur $p. Attendu d'après A : `${a.ownerGroup}` / `${a.seLinuxContext}` (appliquer `restorecon` / `chown`)."
                            }
                        )
                    )
                    checklist.add("[Biométrie/Keystore/TEE] Aligner métadonnées `$p` (${a.ownerGroup}, ${a.seLinuxContext})")
                }
            }
        }

        // 7. SELinux AVC présents dans B mais pas dans A
        val avcA = snapshotA.selinuxFindings.filter { it.sourceType == "AVC_DENIED" }.map { it.rawLine }.toSet()
        val avcB = snapshotB.selinuxFindings.filter { it.sourceType == "AVC_DENIED" }.filter { it.rawLine !in avcA }
        avcB.take(40).forEach { finding ->
            val ruleHint = if (finding.domain != null && finding.targetType != null && finding.tclass != null) {
                "allow ${finding.domain} ${finding.targetType}:${finding.tclass} { ${finding.permission ?: "*"} };"
            } else {
                "Vérifier la règle SELinux correspondante"
            }
            diffs.add(
                ComparisonDiffItem(
                    id = "diff_avc_${diffs.size}",
                    category = DiffCategory.SELINUX_OU_DEPENDANCE,
                    layer = SystemLayer.SELINUX,
                    severity = SeverityLevel.CRITIQUE,
                    keyOrPath = "AVC Denied (${finding.domain ?: "?"} -> ${finding.targetType ?: "?"})",
                    valueA = "Aucun refus identique",
                    valueB = finding.rawLine.take(180),
                    portingNote = "Règle SELinux manquante dans B : `$ruleHint`"
                )
            )
            checklist.add("[SELinux] Ajouter : `$ruleHint`")
        }

        // 8. Anomalies critiques spécifiques à B
        snapshotB.anomalies.filter { it.severity == SeverityLevel.CRITIQUE }.forEach { anom ->
            checklist.add("[${anom.layer.labelFr}] ${anom.title} → ${anom.portingAction}")
        }

        val sortedDiffs = diffs.sortedWith(
            compareBy<ComparisonDiffItem> {
                when (it.severity) {
                    SeverityLevel.CRITIQUE -> 0
                    SeverityLevel.AVERTISSEMENT -> 1
                    SeverityLevel.INFO -> 2
                    SeverityLevel.CONFORME -> 3
                }
            }.thenBy { it.layer.order }
        )

        val layerVerdicts = buildLayerVerdicts(
            a = snapshotA,
            b = snapshotB,
            diffs = sortedDiffs,
            missingClassesInB = missingClassesInB,
            missingConfigKeysInB = missingConfigKeysInB,
            missingServicesInB = missingServicesInB
        )
        val gsiSummary = buildGsiFailureSummary(snapshotA, snapshotB, layerVerdicts)
        val patches = generateImitationPatches(
            a = snapshotA,
            b = snapshotB,
            diffs = sortedDiffs,
            missingConfigKeysInB = missingConfigKeysInB,
            avcB = avcB
        )
        val planMd = buildImplementationPlanMarkdown(snapshotA, snapshotB, gsiSummary, layerVerdicts, patches, checklist.toList())
        val md = buildComparisonMarkdown(snapshotA, snapshotB, gsiSummary, layerVerdicts, sortedDiffs, patches, checklist.toList())

        return ComparisonReport(
            snapshotA = snapshotA.metadata,
            snapshotB = snapshotB.metadata,
            criticalBlockersCount = sortedDiffs.count { it.severity == SeverityLevel.CRITIQUE },
            missingInBCount = sortedDiffs.count { it.category == DiffCategory.MANQUANT_DANS_B },
            modifiedShaCount = sortedDiffs.count { it.category == DiffCategory.MODIFIE_SHA256 },
            propertyDeltaCount = sortedDiffs.count { it.category == DiffCategory.PROPRIETE_DIVERGENTE },
            diffs = sortedDiffs,
            portingChecklistFr = checklist.toList(),
            reportMarkdown = md,
            gsiFailureSummary = gsiSummary,
            layerVerdicts = layerVerdicts,
            generatedPatches = patches,
            implementationPlanMarkdown = planMd,
            deepFindingsCount = sortedDiffs.count {
                it.category == DiffCategory.HAL_SERVICE_OU_SYSTEME ||
                    it.category == DiffCategory.BIO_KEYSTORE_TEE ||
                    it.category == DiffCategory.SELINUX_OU_DEPENDANCE
            }
        )
    }

    private fun formatProtectedMeta(m: ProtectedAreaMetadata): String {
        return if (!m.exists) {
            "Absent"
        } else {
            "Présent • perms=${m.permissions} • owner=${m.ownerGroup} • ctx=${m.seLinuxContext} (${m.entryCount} entrées)"
        }
    }

    private fun extractServiceTokens(snap: FodSnapshot): Set<String> {
        val raw = (snap.liveDumps["lshal_services"].orEmpty() + "\n" +
            snap.liveDumps["service_list"].orEmpty() + "\n" +
            snap.liveDumps["keystore_gatekeeper_tee_services"].orEmpty() + "\n" +
            snap.liveDumps["vintf_statique"].orEmpty())
        return raw.lines()
            .map { it.trim() }
            .filter { it.length >= 6 }
            .map { line -> line.replace(Regex("^\\d+\\s+"), "").trim() }
            .toSet()
    }

    private fun buildLayerVerdicts(
        a: FodSnapshot,
        b: FodSnapshot,
        diffs: List<ComparisonDiffItem>,
        missingClassesInB: List<String>,
        missingConfigKeysInB: List<String>,
        missingServicesInB: List<String>
    ): List<GsiBlockerVerdict> {
        val verdicts = mutableListOf<GsiBlockerVerdict>()

        for (layer in SystemLayer.entries) {
            val nodeA = a.nodes.find { it.layer == layer }
            val nodeB = b.nodes.find { it.layer == layer }
            val layerDiffs = diffs.filter { it.layer == layer }
            val critCount = layerDiffs.count { it.severity == SeverityLevel.CRITIQUE }
            val missCount = layerDiffs.count { it.category == DiffCategory.MANQUANT_DANS_B }

            val statusA = nodeA?.status?.labelFr ?: if (a.artifacts.any { it.layer == layer }) "Actif" else "Non relevé"
            val statusB = nodeB?.status?.labelFr ?: if (b.artifacts.any { it.layer == layer }) "Actif" else "Non relevé"
            val isBrokenB = nodeB?.status == NodeStatus.MANQUANT || nodeB?.status == NodeStatus.CASSE || critCount > 0

            val (cause, evA, evB, solution) = when (layer) {
                SystemLayer.FRAMEWORK -> {
                    val rroA = a.artifacts.filter { it.dexRroAnalysis?.rroTargetPackage != null }.map { it.path.substringAfterLast('/') }
                    val rroB = b.artifacts.filter { it.dexRroAnalysis?.rroTargetPackage != null }.map { it.path.substringAfterLast('/') }
                    val c = buildString {
                        if (rroA.isNotEmpty() && (rroA - rroB.toSet()).isNotEmpty()) {
                            append("Overlay(s) RRO constructeur absent(s) dans le GSI (${(rroA - rroB.toSet()).joinToString(", ")}). ")
                        }
                        if (missingClassesInB.isNotEmpty()) {
                            append("${missingClassesInB.size} classes DEX UDFPS/FOD absentes de SystemUI/Framework B. ")
                        }
                        if (missingConfigKeysInB.isNotEmpty()) {
                            append("${missingConfigKeysInB.size} clés config_udfps/FOD absentes des ressources.")
                        }
                        if (isEmpty()) append(if (isBrokenB) "UDFPS non configuré côté Framework/SystemUI dans B." else "Couche Framework alignée.")
                    }
                    listOf(
                        c,
                        nodeA?.details ?: "${rroA.size} RRO, ${a.artifacts.count { it.layer == layer }} artefacts",
                        nodeB?.details ?: "${rroB.size} RRO, ${b.artifacts.count { it.layer == layer }} artefacts",
                        "Créer/porter un overlay RRO ciblant com.android.systemui et framework-res avec les clés config_udfps* exactes de A (voir patchs_proposes/fod_rro_overlay_config.xml) et activer le gestionnaire UDFPS compatible."
                    )
                }
                SystemLayer.HAL -> {
                    val c = if (missingServicesInB.isNotEmpty()) {
                        "${missingServicesInB.size} interface(s) HAL/Binder enregistrée(s) dans A absente(s) dans B (ex: ${missingServicesInB.take(3).joinToString(", ")})."
                    } else if (isBrokenB) {
                        "Le service HAL biométrique ne s'enregistre pas sur le GSI (${nodeB?.details ?: "absent"})."
                    } else {
                        "Service HAL actif sur les deux systèmes."
                    }
                    listOf(
                        c,
                        nodeA?.details ?: "HAL actif",
                        nodeB?.details ?: "HAL inactif",
                        "Vérifier le manifeste VINTF, le bloc `service` dans init.rc et le chargement des bibliothèques vendor/VNDK du HAL."
                    )
                }
                SystemLayer.VENDOR -> {
                    val missElfs = layerDiffs.filter { it.category == DiffCategory.MANQUANT_DANS_B }.map { it.keyOrPath.substringAfterLast('/') }
                    val brokenDeps = b.artifacts.flatMap { it.elfAnalysis?.missingLibraries.orEmpty() }.distinct()
                    val c = when {
                        brokenDeps.isNotEmpty() -> "Dépendances ELF DT_NEEDED cassées sur B : ${brokenDeps.joinToString(", ")}."
                        missElfs.isNotEmpty() -> "${missElfs.size} fichier(s)/lib(s) vendor de A non présent(s) ou non indexé(s) sur B."
                        else -> "Bibliothèques et binaires vendor cohérents ($missCount absents)."
                    }
                    listOf(
                        c,
                        nodeA?.details ?: "${a.artifacts.count { it.layer == layer }} artefacts vendor",
                        nodeB?.details ?: "${b.artifacts.count { it.layer == layer }} artefacts vendor",
                        "Porter les bibliothèques .so manquantes depuis fichiers_a_porter_de_A/ et vérifier les namespaces dans /vendor/etc/ld.config.txt."
                    )
                }
                SystemLayer.DISPLAY -> {
                    val dispA = a.artifacts.filter { it.layer == SystemLayer.DISPLAY }.map { it.path }
                    val dispB = b.artifacts.filter { it.layer == SystemLayer.DISPLAY }.map { it.path }
                    val missingNodes = dispA - dispB.toSet()
                    val c = if (missingNodes.isNotEmpty() || isBrokenB) {
                        "Contrôle HBM/LHBM / SurfaceFlinger divergent : ${missingNodes.size} nœud(s) ou hook(s) d'illumination d'origine non exploité(s) dans B."
                    } else {
                        "Nœuds d'affichage HBM/LHBM accessibles."
                    }
                    listOf(
                        c,
                        dispA.take(4).joinToString(", ").ifBlank { nodeA?.details ?: "Nœuds affichage" },
                        dispB.take(4).joinToString(", ").ifBlank { nodeB?.details ?: "Aucun HBM détecté" },
                        "Adapter le hook UDFPS Display HBM/LHBM du GSI pour écrire sur les mêmes nœuds sysfs / appels SurfaceFlinger que A (voir fod_hal_display_touch_hook.txt)."
                    )
                }
                SystemLayer.TOUCH -> {
                    val touchA = a.artifacts.filter { it.layer == SystemLayer.TOUCH }.map { it.path }
                    val touchB = b.artifacts.filter { it.layer == SystemLayer.TOUCH }.map { it.path }
                    val c = if ((touchA - touchB.toSet()).isNotEmpty() || isBrokenB) {
                        "Notification tactile FOD (fod_status / BTN_FINGERPRINT / TouchFeature) manquante ou non reliée dans le GSI."
                    } else {
                        "Chaîne tactile FOD présente."
                    }
                    listOf(
                        c,
                        touchA.take(4).joinToString(", ").ifBlank { nodeA?.details ?: "Tactile actif" },
                        touchB.take(4).joinToString(", ").ifBlank { nodeB?.details ?: "Tactile FOD absent" },
                        "Relier l'état UDFPS (onFingerDown / onFingerUp) au pilote tactile ou nœud sysfs/HAL utilisé par A."
                    )
                }
                SystemLayer.KERNEL -> {
                    val c = if (isBrokenB || missCount > 0) {
                        "$missCount nœud(s) noyau/sysfs ou modules présents dans A divergent sur B."
                    } else {
                        "Noyau, /dev et sysfs biométriques compatibles."
                    }
                    listOf(
                        c,
                        nodeA?.details ?: "Noyau A",
                        nodeB?.details ?: "Noyau B",
                        "Conserver les permissions chmod/chown sur /dev/* et /sys/* dans fod_init_overlay.rc."
                    )
                }
                SystemLayer.DEVICE_TREE -> {
                    val dtA = a.artifacts.filter { it.layer == SystemLayer.DEVICE_TREE }.size
                    val dtB = b.artifacts.filter { it.layer == SystemLayer.DEVICE_TREE }.size
                    val c = if (dtA > 0 && dtB == 0) {
                        "Nœuds Device Tree visibles dans A ($dtA) mais inaccessibles dans B (vérifier Root sur GSI)."
                    } else {
                        "Device Tree matériel partagé ($dtA nœuds dans A vs $dtB dans B)."
                    }
                    listOf(c, "$dtA nœuds FDT", "$dtB nœuds FDT", "Utiliser les propriétés compatible/GPIO/régulateurs extraites de A (quasi_code_source/devicetree) pour vérifier le matching du pilote.")
                }
                SystemLayer.SELINUX -> {
                    val avcCount = layerDiffs.count { it.category == DiffCategory.SELINUX_OU_DEPENDANCE }
                    val bioMetaDiffs = layerDiffs.count { it.category == DiffCategory.BIO_KEYSTORE_TEE }
                    val c = buildString {
                        if (avcCount > 0) append("$avcCount refus SELinux (avc: denied) actifs dans le GSI B. ")
                        if (bioMetaDiffs > 0) append("$bioMetaDiffs divergence(s) de contexte SELinux/ownership sur fpdata/keystore/persist/TEE.")
                        if (isEmpty()) append("Politique SELinux et contextes biométrie/keystore alignés.")
                    }
                    listOf(
                        c,
                        "SELinux ${a.metadata.seLinuxMode} • 0 refus bloquants",
                        "SELinux ${b.metadata.seLinuxMode} • $avcCount AVC / $bioMetaDiffs écarts métadonnées",
                        "Injecter les règles `allow` et `restorecon` générées dans `fod_sepolicy_gsi.te` et `fod_init_overlay.rc`."
                    )
                }
            }

            verdicts.add(
                GsiBlockerVerdict(
                    id = "verdict_${layer.name}",
                    layer = layer,
                    title = layer.labelFr,
                    statusInA = statusA,
                    statusInB = statusB,
                    isBlocking = isBrokenB,
                    rootCause = cause,
                    evidenceA = evA,
                    evidenceB = evB,
                    imitationSolution = solution
                )
            )
        }
        return verdicts
    }

    private fun buildGsiFailureSummary(
        a: FodSnapshot,
        b: FodSnapshot,
        verdicts: List<GsiBlockerVerdict>
    ): String {
        val blockers = verdicts.filter { it.isBlocking }
        val sb = StringBuilder()
        sb.appendLine("Comparaison factuelle : ${a.metadata.displayName} (Référence A) ➔ ${b.metadata.displayName} (Cible GSI B).")
        if (blockers.isEmpty()) {
            sb.appendLine("Aucune rupture critique majeure détectée automatiquement entre A et B ; vérifier les écarts SHA-256 ou propriétés mineures ci-dessous.")
        } else {
            sb.appendLine("${blockers.size} couche(s) critique(s) expliquent pourquoi le FOD échoue sur le GSI :")
            blockers.forEachIndexed { idx, v ->
                sb.appendLine("${idx + 1}. [${v.title}] ${v.rootCause}")
            }
        }
        return sb.toString().trim()
    }

    private fun generateImitationPatches(
        a: FodSnapshot,
        b: FodSnapshot,
        diffs: List<ComparisonDiffItem>,
        missingConfigKeysInB: List<String>,
        avcB: List<com.example.model.SelinuxFinding>
    ): List<GeneratedPatchArtifact> {
        val patches = mutableListOf<GeneratedPatchArtifact>()

        // 1. Patch SELinux (.te)
        val teLines = LinkedHashSet<String>()
        avcB.forEach { f ->
            if (!f.domain.isNullOrBlank() && !f.targetType.isNullOrBlank() && !f.tclass.isNullOrBlank() && !f.permission.isNullOrBlank()) {
                teLines.add("allow ${f.domain} ${f.targetType}:${f.tclass} { ${f.permission} };")
            }
        }
        val aCtxLines = a.liveDumps["selinux_contexts"].orEmpty().lines().filter { it.isNotBlank() }.take(30)
        val seContent = buildString {
            appendLine("# Patch SELinux généré automatiquement depuis la comparaison A -> B")
            appendLine("# À injecter via magiskpolicy --live / sepolicy-inject ou dans plat_sepolicy / vendor_sepolicy")
            appendLine()
            if (teLines.isEmpty()) {
                appendLine("# Aucun refus avc: denied capturé dans B (relancer l'analyse sur GSI juste après une tentative de scan d'empreinte si besoin).")
            } else {
                teLines.forEach { appendLine(it) }
            }
            if (aCtxLines.isNotEmpty()) {
                appendLine()
                appendLine("# Contextes de référence relevés dans la ROM d'origine A (file_contexts / hwservice_contexts) :")
                aCtxLines.forEach { appendLine("# $it") }
            }
        }
        patches.add(
            GeneratedPatchArtifact(
                id = "patch_sepolicy",
                fileName = "fod_sepolicy_gsi.te",
                title = "Règles SELinux & contextes (.te)",
                kind = "SELinux Policy",
                targetPathHint = "/vendor/etc/selinux/ ou magiskpolicy",
                description = "Autorise les accès HAL, sysfs, display, tactile, fpdata et keystore bloqués par SELinux sur le GSI.",
                codeContent = seContent
            )
        )

        // 2. Patch propriétés système (system.prop / resetprop)
        val propDiffs = diffs.filter { it.category == DiffCategory.PROPRIETE_DIVERGENTE && it.valueA != "<non défini>" }
        val propContent = buildString {
            appendLine("# Propriétés FOD / UDFPS / Affichage / Tactile de la ROM A absentes ou modifiées dans B")
            appendLine("# Utilisable dans system.prop d'un module Magisk ou via `resetprop <clé> <valeur>`")
            appendLine()
            if (propDiffs.isEmpty()) {
                appendLine("# Toutes les propriétés FOD de A sont déjà présentes avec la même valeur dans B.")
            } else {
                propDiffs.forEach { d ->
                    appendLine("${d.keyOrPath}=${d.valueA}")
                }
            }
        }
        patches.add(
            GeneratedPatchArtifact(
                id = "patch_props",
                fileName = "fod_system_props.prop",
                title = "Propriétés système d'imitation (system.prop)",
                kind = "Propriétés / resetprop",
                targetPathHint = "module_magisk/system.prop",
                description = "${propDiffs.size} propriété(s) FOD/HBM/Vendor à restaurer à l'identique de la ROM d'origine.",
                codeContent = propContent
            )
        )

        // 3. Patch RRO Overlay XML
        val rrosA = a.artifacts.mapNotNull { it.dexRroAnalysis }.filter {
            it.rroTargetPackage != null || it.matchedConfigKeys.isNotEmpty() || it.decodedRroXml.isNotBlank()
        }
        val rroContent = buildString {
            appendLine("<!-- Ébauche RRO / Overlay UDFPS générée depuis la capture A (${a.metadata.displayName}) -->")
            appendLine("<resources>")
            rrosA.forEach { dr ->
                appendLine("    <!-- Source : ${dr.sourcePath} | Cible : ${dr.rroTargetPackage ?: dr.packageName ?: "com.android.systemui"} (priorité=${dr.rroPriority ?: "10"}) -->")
                dr.udfpsProperties.forEach { (k, v) ->
                    appendLine("    <!-- Prop DEX/AXML : $k = $v -->")
                }
            }
            if (missingConfigKeysInB.isNotEmpty()) {
                appendLine("    <!-- Clés présentes dans A et manquantes dans B : -->")
                missingConfigKeysInB.take(40).forEach { key ->
                    appendLine("    <item name=\"$key\" type=\"config\">À_ALIGNER_AVEC_A</item>")
                }
            }
            appendLine("</resources>")
            rrosA.firstOrNull { it.decodedRroXml.isNotBlank() }?.decodedRroXml?.let { sampleXml ->
                appendLine()
                appendLine("<!-- Extrait XML décodé depuis la ROM d'origine A : -->")
                appendLine(sampleXml.take(3000))
            }
        }
        patches.add(
            GeneratedPatchArtifact(
                id = "patch_rro",
                fileName = "fod_rro_overlay_config.xml",
                title = "Configuration Overlay RRO SystemUI / Framework",
                kind = "Overlay RRO XML",
                targetPathHint = "/product/overlay/ ou /vendor/overlay/",
                description = "Regroupe les cibles RRO et clés `config_udfps*` extraites de A pour aligner l'UI, la position du capteur et l'illumination sur le GSI.",
                codeContent = rroContent
            )
        )

        // 4. Patch init.rc + alignement permissions/contextes fpdata/keystore/persist/TEE
        val rcArtsA = a.artifacts.filter { it.path.endsWith(".rc") && !b.artifacts.any { bArt -> bArt.path == it.path && bArt.sha256 == it.sha256 } }
        val bioAuditsA = a.protectedAreaAudits.filter { it.exists }
        val rcContent = buildString {
            appendLine("# Patch Init (.rc) pour services HAL FOD + alignement structurel fpdata / keystore / persist / TEE")
            appendLine("# Basé strictement sur les métadonnées observées dans la ROM d'origine A")
            appendLine()
            if (bioAuditsA.isNotEmpty()) {
                appendLine("on post-fs-data")
                bioAuditsA.forEach { area ->
                    val modeMatch = Regex("\\(([0-7]{3,4})\\)").find(area.permissions)?.groupValues?.getOrNull(1) ?: "0770"
                    val ownerParts = area.ownerGroup.split(':')
                    val uid = ownerParts.getOrNull(0)?.takeIf { it.isNotBlank() && it != "?" } ?: "system"
                    val gid = ownerParts.getOrNull(1)?.takeIf { it.isNotBlank() && it != "?" } ?: "system"
                    if (!area.path.startsWith("/dev/")) {
                        appendLine("    mkdir ${area.path} $modeMatch $uid $gid")
                    }
                    appendLine("    chown $uid $gid ${area.path}")
                    appendLine("    restorecon_recursive ${area.path} # Contexte attendu A : ${area.seLinuxContext}")
                }
                appendLine()
            }
            if (rcArtsA.isNotEmpty()) {
                rcArtsA.forEach { rc ->
                    appendLine("# --- Extrait de ${rc.path} ---")
                    appendLine(rc.rawExcerpt.take(2500))
                    appendLine()
                }
            }
        }
        patches.add(
            GeneratedPatchArtifact(
                id = "patch_init_rc",
                fileName = "fod_init_overlay.rc",
                title = "Script Init HAL & permissions fpdata/Keystore/TEE",
                kind = "Init .rc",
                targetPathHint = "/vendor/etc/init/ ou service Magisk post-fs-data",
                description = "Reproduit le démarrage HAL FOD et les permissions/contextes structurels de `fpdata`, `keystore`, `persist` et `tee` observés sur A.",
                codeContent = rcContent
            )
        )

        // 5. Hook Display HBM/LHBM & Touch & HAL
        val dispNodesA = a.artifacts.filter { it.layer == SystemLayer.DISPLAY }.map { "${it.path} (${it.summary})" }
        val touchNodesA = a.artifacts.filter { it.layer == SystemLayer.TOUCH }.map { "${it.path} (${it.summary})" }
        val halExportsA = a.artifacts.filter { it.layer == SystemLayer.HAL || it.layer == SystemLayer.VENDOR }
            .flatMap { art -> art.elfAnalysis?.exportedSymbols.orEmpty().map { "${art.path.substringAfterLast('/')} :: $it" } }
            .take(35)
        val hookContent = buildString {
            appendLine("# Spécification technique des hooks Display HBM/LHBM, Tactile et HAL à imiter sur GSI")
            appendLine()
            appendLine("[NOEUDS AFFICHAGE HBM / LHBM / DRM DANS A]")
            if (dispNodesA.isEmpty()) appendLine("- Aucun nœud spécifique relevé") else dispNodesA.forEach { appendLine("- $it") }
            appendLine()
            appendLine("[NOEUDS TACTILES & ÉVÉNEMENTS DANS A]")
            if (touchNodesA.isEmpty()) appendLine("- Aucun nœud spécifique relevé") else touchNodesA.forEach { appendLine("- $it") }
            appendLine()
            appendLine("[SYMBOLES C/C++ EXPORTÉS PAR LES HAL/LIBS DE A]")
            if (halExportsA.isEmpty()) appendLine("- Aucun symbole exporté relevé") else halExportsA.forEach { appendLine("- $it") }
        }
        patches.add(
            GeneratedPatchArtifact(
                id = "patch_hooks",
                fileName = "fod_hal_display_touch_hook.txt",
                title = "Cartographie des hooks HBM, Tactile & HAL",
                kind = "Spécification Hooks",
                targetPathHint = "SystemUI UdfpsHandler / Vendor HAL",
                description = "Liste les nœuds sysfs HBM/tactiles et les symboles C++ exacts utilisés par la ROM A.",
                codeContent = hookContent
            )
        )

        // 6. Manifeste exact des fichiers à porter depuis A
        val mapB = b.artifacts.associateBy { it.path }
        val filesToPort = a.artifacts.filter { artA ->
            !BiometricPrivacyGuard.isProtectedBiometricPath(artA.path) &&
                (mapB[artA.path] == null || mapB[artA.path]?.sha256 != artA.sha256)
        }
        val portListContent = buildString {
            appendLine("# Liste des fichiers manquants ou divergents dans B à porter / adapter depuis A")
            appendLine("# Note : les fichiers non-secrets extraits sont copiés dans fichiers_a_porter_de_A/ dans l'archive ZIP.")
            appendLine()
            filesToPort.forEach { art ->
                val reason = if (mapB[art.path] == null) "ABSENT_DANS_B" else "SHA256_DIFFERENT"
                appendLine("[$reason] [${art.layer.labelFr}] ${art.path} | sha256=${art.sha256} | extrait=${art.extractedRelativePath ?: "non"}")
            }
        }
        patches.add(
            GeneratedPatchArtifact(
                id = "patch_port_list",
                fileName = "liste_fichiers_a_porter.txt",
                title = "Manifeste des fichiers & .so à porter (${filesToPort.size})",
                kind = "Inventaire de portage",
                targetPathHint = "fichiers_a_porter_de_A/",
                description = "Inventaire complet des bibliothèques `.so`, HAL, overlays et scripts absents ou modifiés dans le GSI.",
                codeContent = portListContent
            )
        )

        return patches
    }

    private fun buildImplementationPlanMarkdown(
        a: FodSnapshot,
        b: FodSnapshot,
        gsiSummary: String,
        verdicts: List<GsiBlockerVerdict>,
        patches: List<GeneratedPatchArtifact>,
        checklist: List<String>
    ): String {
        val sb = StringBuilder()
        sb.appendLine("# PLAN D'IMPLÉMENTATION & D'IMITATION FOD 100 % — ROM A ➔ GSI B")
        sb.appendLine()
        sb.appendLine("- **ROM de référence fonctionnelle (A)** : `${a.metadata.displayName}` (`${a.metadata.buildFingerprint}`)")
        sb.appendLine("- **GSI / Système cible (B)** : `${b.metadata.displayName}` (`${b.metadata.buildFingerprint}`)")
        sb.appendLine("- **Politique biométrique** : Aucun gabarit `fpdata` ni clé privée Keystore n'est exporté (audit structurel métadonnées uniquement).")
        sb.appendLine()
        sb.appendLine("## 1. Pourquoi le FOD échoue sur le GSI sideloadé")
        sb.appendLine(gsiSummary)
        sb.appendLine()
        sb.appendLine("## 2. Diagnostic causal par couche")
        verdicts.forEach { v ->
            val tag = if (v.isBlocking) "BLOQUANT" else "OK"
            sb.appendLine("### [$tag] ${v.title}")
            sb.appendLine("- **État A** : ${v.statusInA} (`${v.evidenceA}`)")
            sb.appendLine("- **État B** : ${v.statusInB} (`${v.evidenceB}`)")
            sb.appendLine("- **Cause racine** : ${v.rootCause}")
            sb.appendLine("- **Solution d'imitation** : ${v.imitationSolution}")
            sb.appendLine()
        }
        sb.appendLine("## 3. Plan d'action ordonné pour reproduire le FOD à 100 %")
        checklist.forEachIndexed { idx, step ->
            sb.appendLine("${idx + 1}. $step")
        }
        sb.appendLine()
        sb.appendLine("## 4. Patchs & fichiers prêts à adapter (dossier `patchs_proposes/`)")
        patches.forEach { p ->
            sb.appendLine("### `${p.fileName}` — ${p.title}")
            sb.appendLine("- **Cible** : `${p.targetPathHint}`")
            sb.appendLine("- **Rôle** : ${p.description}")
            sb.appendLine("```text\n${p.codeContent.take(3500)}\n```")
            sb.appendLine()
        }
        return sb.toString()
    }

    private fun buildComparisonMarkdown(
        a: FodSnapshot,
        b: FodSnapshot,
        gsiSummary: String,
        verdicts: List<GsiBlockerVerdict>,
        diffs: List<ComparisonDiffItem>,
        patches: List<GeneratedPatchArtifact>,
        checklist: List<String>
    ): String {
        val sb = StringBuilder()
        sb.appendLine("# RAPPORT DE COMPARAISON FOD ULTRA-COMPLET — A vs B")
        sb.appendLine("- **Référence A** : `${a.metadata.displayName}` (`${a.metadata.id}`)")
        sb.appendLine("- **Cible B** : `${b.metadata.displayName}` (`${b.metadata.id}`)")
        sb.appendLine()
        sb.appendLine("## Résumé factuel du blocage sur le GSI")
        sb.appendLine(gsiSummary)
        sb.appendLine()
        sb.appendLine("## Verdicts par couche système")
        verdicts.forEach { v ->
            val icon = if (v.isBlocking) "BLOQUANT" else "CONFORME"
            sb.appendLine("- **[$icon] ${v.title}** : ${v.rootCause} → *${v.imitationSolution}*")
        }
        sb.appendLine()
        sb.appendLine("## Synthèse des écarts factuels")
        sb.appendLine("- Bloquants critiques : **${diffs.count { it.severity == SeverityLevel.CRITIQUE }}**")
        sb.appendLine("- Présents dans A, absents dans B : **${diffs.count { it.category == DiffCategory.MANQUANT_DANS_B }}**")
        sb.appendLine("- Modifiés (SHA-256) : **${diffs.count { it.category == DiffCategory.MODIFIE_SHA256 }}**")
        sb.appendLine("- Propriétés divergentes : **${diffs.count { it.category == DiffCategory.PROPRIETE_DIVERGENTE }}**")
        sb.appendLine("- Écarts profonds (HAL/DEX/RRO/SELinux/Biométrie-Keystore) : **${diffs.count { it.category == DiffCategory.HAL_SERVICE_OU_SYSTEME || it.category == DiffCategory.BIO_KEYSTORE_TEE || it.category == DiffCategory.SELINUX_OU_DEPENDANCE }}**")
        sb.appendLine()
        sb.appendLine("## Liste de contrôle de portage (actions concrètes)")
        checklist.forEachIndexed { i, item ->
            sb.appendLine("${i + 1}. $item")
        }
        sb.appendLine()
        sb.appendLine("## Patchs générés (${patches.size})")
        patches.forEach { p ->
            sb.appendLine("- `${p.fileName}` (${p.targetPathHint}) : ${p.description}")
        }
        sb.appendLine()
        sb.appendLine("## Détail complet des écarts (${diffs.size})")
        diffs.forEach { d ->
            sb.appendLine("### [${d.severity.labelFr}] ${d.keyOrPath} (${d.category.labelFr})")
            sb.appendLine("- **A** : `${d.valueA}`")
            sb.appendLine("- **B** : `${d.valueB}`")
            sb.appendLine("- **Note** : ${d.portingNote}")
            sb.appendLine()
        }
        return sb.toString()
    }
}

package com.example.core

import com.example.model.ComparisonDiffItem
import com.example.model.ComparisonReport
import com.example.model.DiffCategory
import com.example.model.FodSnapshot
import com.example.model.SeverityLevel
import com.example.model.SystemLayer

object FodComparatorEngine {

    fun compare(snapshotA: FodSnapshot, snapshotB: FodSnapshot): ComparisonReport {
        val diffs = mutableListOf<ComparisonDiffItem>()
        val checklist = LinkedHashSet<String>()

        val mapA = snapshotA.artifacts.associateBy { it.path }
        val mapB = snapshotB.artifacts.associateBy { it.path }

        // 1. Présent dans A (ex: ROM Stock), absent dans B (ex: GSI)
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
                        "Binaire/Lib ELF absent dans B. Dépendances requises : ${artA.elfAnalysis.neededLibraries.joinToString(", ")}."
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
                    val note = if (elfMissDiff.isNotEmpty()) {
                        "SHA-256 différent ET nouvelles dépendances ELF manquantes dans B : ${elfMissDiff.joinToString(", ")}."
                    } else {
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
                            "Valeur divergente entre A et B."
                        }
                    )
                )
                if (valA != null && valB == null && (key.contains("finger") || key.contains("udfps") || key.contains("fod") || key.contains("hbm"))) {
                    checklist.add("[Propriété] Définir `$key=$valA` sur le système cible")
                }
            }
        }

        // 4. SELinux AVC présents dans B mais pas dans A
        val avcA = snapshotA.selinuxFindings.filter { it.sourceType == "AVC_DENIED" }.map { it.rawLine }.toSet()
        val avcB = snapshotB.selinuxFindings.filter { it.sourceType == "AVC_DENIED" }.filter { it.rawLine !in avcA }
        avcB.take(30).forEach { finding ->
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

        // 5. Anomalies critiques spécifiques à B
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

        val md = buildComparisonMarkdown(snapshotA, snapshotB, sortedDiffs, checklist.toList())

        return ComparisonReport(
            snapshotA = snapshotA.metadata,
            snapshotB = snapshotB.metadata,
            criticalBlockersCount = sortedDiffs.count { it.severity == SeverityLevel.CRITIQUE },
            missingInBCount = sortedDiffs.count { it.category == DiffCategory.MANQUANT_DANS_B },
            modifiedShaCount = sortedDiffs.count { it.category == DiffCategory.MODIFIE_SHA256 },
            propertyDeltaCount = sortedDiffs.count { it.category == DiffCategory.PROPRIETE_DIVERGENTE },
            diffs = sortedDiffs,
            portingChecklistFr = checklist.toList(),
            reportMarkdown = md
        )
    }

    private fun buildComparisonMarkdown(
        a: FodSnapshot,
        b: FodSnapshot,
        diffs: List<ComparisonDiffItem>,
        checklist: List<String>
    ): String {
        val sb = StringBuilder()
        sb.appendLine("# RAPPORT DE COMPARAISON FOD — A vs B")
        sb.appendLine("- **Référence A** : `${a.metadata.displayName}` (`${a.metadata.id}`)")
        sb.appendLine("- **Cible B** : `${b.metadata.displayName}` (`${b.metadata.id}`)")
        sb.appendLine()
        sb.appendLine("## Synthèse des écarts factuels")
        sb.appendLine("- Bloquants critiques : **${diffs.count { it.severity == SeverityLevel.CRITIQUE }}**")
        sb.appendLine("- Présents dans A, absents dans B : **${diffs.count { it.category == DiffCategory.MANQUANT_DANS_B }}**")
        sb.appendLine("- Modifiés (SHA-256) : **${diffs.count { it.category == DiffCategory.MODIFIE_SHA256 }}**")
        sb.appendLine("- Propriétés divergentes : **${diffs.count { it.category == DiffCategory.PROPRIETE_DIVERGENTE }}**")
        sb.appendLine()
        sb.appendLine("## Liste de contrôle de portage (actions concrètes)")
        checklist.forEachIndexed { i, item ->
            sb.appendLine("${i + 1}. $item")
        }
        sb.appendLine()
        sb.appendLine("## Détail complet des écarts")
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

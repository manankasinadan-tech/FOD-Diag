package com.example.livefod

object LiveFodComparator {

    fun compare(sessionA: LiveFodSession, sessionB: LiveFodSession): LiveComparisonReport {
        val items = mutableListOf<LiveComparisonDiffItem>()

        // 1. Comparaison étape par étape de la chaîne d'interaction réelle
        val hopsA = sessionA.mechanism.hops.associateBy { it.order }
        val hopsB = sessionB.mechanism.hops.associateBy { it.order }
        val allOrders = (hopsA.keys + hopsB.keys).sorted()

        for (ord in allOrders) {
            val hA = hopsA[ord]
            val hB = hopsB[ord]
            if (hA != null && hB != null) {
                val brokenInB = (hA.outcome == LiveOutcome.REACTION_DETECTEE || hA.outcome == LiveOutcome.TRANSITION_ETAT) &&
                    (hB.outcome == LiveOutcome.SILENCE_RADIO || hB.outcome == LiveOutcome.ERREUR_EXPLICITE)
                if (brokenInB || hA.outcome != hB.outcome) {
                    items.add(
                        LiveComparisonDiffItem(
                            id = "cmp_hop_$ord",
                            domain = "Chaîne d'exécution (${hA.layerTag})",
                            subject = "Étape $ord : ${hA.hopName}",
                            valueInA = "[${hA.outcome.labelFr}] ${hA.factualEvidence}",
                            valueInB = "[${hB.outcome.labelFr}] ${hB.factualEvidence}",
                            isCriticalBlocker = brokenInB || hB.outcome == LiveOutcome.ERREUR_EXPLICITE,
                            factualExplanation = if (brokenInB) {
                                "Dans la session A, cette étape a réagi normalement (${hA.actorsObserved.take(3).joinToString(", ")}), alors que dans B elle est ${hB.outcome.labelFr}."
                            } else {
                                "Divergence d'exécution observée entre A (${hA.outcome.labelFr}) et B (${hB.outcome.labelFr})."
                            },
                            imitationAction = "Comparer les acteurs de A (${hA.actorsObserved.take(4).joinToString(", ")}) et leurs fichiers (${hA.filesAndNodesInvolved.take(3).joinToString(", ")}) avec B."
                        )
                    )
                }
            }
        }

        // 2. Fichiers réellement appelés / chargés dans la chaîne de A vs B
        val filesA = sessionA.extractedFiles.associateBy { it.originalPath }
        val filesB = sessionB.extractedFiles.associateBy { it.originalPath }
        val mappedBAll = sessionB.halProcesses.flatMap { it.mappedFiles }.toSet()

        for ((path, fA) in filesA) {
            if (path.startsWith("/proc/device-tree")) continue
            val fB = filesB[path]
            val loadedInB = path in mappedBAll || fB != null
            if (!loadedInB) {
                val critical = fA.originalPath.endsWith(".so") || fA.originalPath.endsWith(".rc") || fA.originalPath.endsWith(".apk")
                items.add(
                    LiveComparisonDiffItem(
                        id = "cmp_file_${items.size}",
                        domain = fA.category,
                        subject = "Non appelé / absent dans B : $path",
                        valueInA = "${fA.kind} | SHA=${fA.sha256.take(12)} | ${fA.reasonInChain}",
                        valueInB = "Jamais chargé ni appelé durant la session B",
                        isCriticalBlocker = critical,
                        factualExplanation = "Ce fichier a été réellement sollicité pendant l'enrôlement sur A (${fA.reasonInChain}), mais n'apparaît pas dans la chaîne de B.",
                        imitationAction = "Porter `$path` (et consulter son code source reconstruit `${fA.sourceCodeRelPath ?: "-"}` dans A)."
                    )
                )
            } else if (fB != null && fA.sha256 != fB.sha256 && fA.sha256 != "INDISPONIBLE" && fB.sha256 != "INDISPONIBLE") {
                items.add(
                    LiveComparisonDiffItem(
                        id = "cmp_sha_${items.size}",
                        domain = fA.category,
                        subject = "Contenu différent : $path",
                        valueInA = "SHA=${fA.sha256.take(16)}",
                        valueInB = "SHA=${fB.sha256.take(16)}",
                        isCriticalBlocker = false,
                        factualExplanation = "Le fichier est présent dans les deux chaînes mais son SHA-256 diffère entre A et B.",
                        imitationAction = "Comparer `${fA.sourceCodeRelPath ?: path}` entre A et B."
                    )
                )
            }
        }

        // 3. Transitions Sysfs observées dans A mais figées / absentes dans B
        val sysfsB = sessionB.sysfsTransitions.associateBy { it.path }
        sessionA.sysfsTransitions.filter { it.hasChanged }.forEach { tA ->
            val tB = sysfsB[tA.path]
            if (tB == null) {
                items.add(
                    LiveComparisonDiffItem(
                        id = "cmp_sysfs_${items.size}",
                        domain = "Noyau & Sysfs (${tA.category})",
                        subject = "Nœud sysfs actif dans A absent de B : ${tA.path}",
                        valueInA = "${tA.beforeValue} -> ${tA.duringValues} -> ${tA.afterValue}",
                        valueInB = "Nœud non détecté",
                        isCriticalBlocker = true,
                        factualExplanation = "Ce nœud sysfs a changé d'état pendant l'enregistrement dans A, prouvant son rôle dans le mécanisme FOD.",
                        imitationAction = "Vérifier le pilote noyau ou les permissions SELinux sur `${tA.path}`."
                    )
                )
            } else if (!tB.hasChanged) {
                items.add(
                    LiveComparisonDiffItem(
                        id = "cmp_sysfs_static_${items.size}",
                        domain = "Noyau & Sysfs (${tA.category})",
                        subject = "Nœud sysfs figé dans B : ${tA.path}",
                        valueInA = "A transité : ${tA.beforeValue} -> ${tA.duringValues} -> ${tA.afterValue}",
                        valueInB = "Figé à '${tB.beforeValue}' (${tB.permissions} | ${tB.seLinuxContext})",
                        isCriticalBlocker = true,
                        factualExplanation = "Le nœud existe dans B mais personne ne l'a basculé pendant l'essai d'empreinte (contrairement à A).",
                        imitationAction = "Vérifier l'accès (`chown`/`chmod`/SELinux `${tA.seLinuxContext}`) et quel daemon de A écrit dans `${tA.path}`."
                    )
                )
            }
        }

        // 4. Erreurs explicites spécifiques à B
        val errA = sessionA.mechanism.errorSignatures.toSet()
        sessionB.mechanism.errorSignatures.filter { it !in errA }.forEach { err ->
            items.add(
                LiveComparisonDiffItem(
                    id = "cmp_err_${items.size}",
                    domain = "Erreur Live B",
                    subject = "Erreur explicite bloquante dans B",
                    valueInA = "Absente dans A",
                    valueInB = err,
                    isCriticalBlocker = true,
                    factualExplanation = "Signature d'erreur directement interceptée dans les journaux temps réel de B durant l'essai.",
                    imitationAction = "Corriger la cause directe indiquée par cette erreur."
                )
            )
        }

        val blockers = items.count { it.isCriticalBlocker }
        val summaryFr = buildString {
            appendLine("Comparaison Live FOD : ${sessionA.metadata.displayName} (A) ➔ ${sessionB.metadata.displayName} (B)")
            appendLine("• Verdict A : ${sessionA.mechanism.enrollmentVerdict} (${sessionA.mechanism.primaryArchitecture})")
            appendLine("• Verdict B : ${sessionB.mechanism.enrollmentVerdict} (${sessionB.mechanism.primaryArchitecture})")
            appendLine("• Écarts détectés en exécution réelle : ${items.size} dont $blockers bloquant(s) critique(s).")
            val hopBlockers = items.filter { it.domain.startsWith("Chaîne") && it.isCriticalBlocker }
            if (hopBlockers.isNotEmpty()) {
                appendLine("• Ruptures de chaîne dans B : ${hopBlockers.joinToString(" ; ") { it.subject }}")
            }
        }.trim()

        val diffPatches = buildDifferentialPatches(sessionA, sessionB, items)
        val md = buildString {
            appendLine("# RAPPORT DE COMPARAISON LIVE FOD (EXÉCUTION RÉELLE A vs B)")
            appendLine()
            appendLine(summaryFr)
            appendLine()
            appendLine("## 1. Différences factuelles d'exécution (${items.size})")
            items.forEachIndexed { idx, it ->
                val tag = if (it.isCriticalBlocker) "BLOQUANT" else "INFO"
                appendLine("### ${idx + 1}. [$tag] ${it.subject} (${it.domain})")
                appendLine("- **A (Référence)** : ${it.valueInA}")
                appendLine("- **B (Cible)** : ${it.valueInB}")
                appendLine("- **Constat** : ${it.factualExplanation}")
                appendLine("- **Action d'imitation** : ${it.imitationAction}")
                appendLine()
            }
            appendLine("## 2. Patchs différentiels générés (${diffPatches.size})")
            diffPatches.forEach { p ->
                appendLine("### ${p.fileName} — ${p.title}")
                appendLine("```")
                appendLine(p.codeContent)
                appendLine("```")
                appendLine()
            }
        }

        return LiveComparisonReport(
            sessionA = sessionA.metadata,
            sessionB = sessionB.metadata,
            causalSummaryFr = summaryFr,
            blockersCount = blockers,
            items = items.sortedByDescending { it.isCriticalBlocker },
            differentialPatches = diffPatches,
            reportMarkdown = md
        )
    }

    private fun buildDifferentialPatches(
        sessionA: LiveFodSession,
        sessionB: LiveFodSession,
        items: List<LiveComparisonDiffItem>
    ): List<LiveGeneratedPatch> {
        val patches = mutableListOf<LiveGeneratedPatch>()

        // 1. Reprendre SELinux de B en priorité
        val seB = sessionB.patches.firstOrNull { it.fileName == "patch_selinux_live.te" }
        patches.add(
            LiveGeneratedPatch(
                id = "diff_live_se",
                fileName = "diff_patch_selinux.te",
                title = "Patch SELinux issu des refus Live de B",
                kind = "SELinux Policy",
                targetPathHint = "magiskpolicy --live / vendor sepolicy",
                description = seB?.description ?: "Règles SELinux issues de l'exécution Live de B.",
                codeContent = seB?.codeContent ?: "# Aucun refus avc: denied capturé dans la session B.\n"
            )
        )

        // 2. Patch sysfs & init issu des nœuds actifs dans A
        val sysfsFromA = sessionA.sysfsTransitions.filter { it.hasChanged }
        val rcDiff = buildString {
            appendLine("# Nœuds sysfs ayant réellement réagi dans A lors de l'enrôlement (à rendre accessibles/actifs dans B)")
            appendLine("on post-fs-data")
            sysfsFromA.forEach { t ->
                appendLine("    # Valeur A pendant scan : ${t.duringValues} | Contexte A : ${t.seLinuxContext}")
                appendLine("    chmod 0664 ${t.path}")
                appendLine("    chown system system ${t.path}")
            }
            sessionA.patches.firstOrNull { it.fileName == "patch_init_et_sysfs_live.rc" }?.let {
                appendLine()
                appendLine("# Référence complète de A :")
                appendLine(it.codeContent)
            }
        }
        patches.add(
            LiveGeneratedPatch(
                id = "diff_live_rc",
                fileName = "diff_patch_sysfs_init.rc",
                title = "Patch Init & Sysfs basé sur les transitions réelles de A",
                kind = "Init & Sysfs",
                targetPathHint = "/vendor/etc/init/ ou service Magisk",
                description = "Aligne les ${sysfsFromA.size} nœuds sysfs actifs dans A sur le GSI B.",
                codeContent = rcDiff
            )
        )

        // 3. Propriétés de A absentes de B
        val propA = sessionA.patches.firstOrNull { it.fileName == "patch_proprietes_live.prop" }
        patches.add(
            LiveGeneratedPatch(
                id = "diff_live_prop",
                fileName = "diff_patch_props.prop",
                title = "Propriétés actives dans la session Live A",
                kind = "Propriétés",
                targetPathHint = "module_magisk/system.prop",
                description = propA?.description ?: "Propriétés système actives durant la session Live A.",
                codeContent = propA?.codeContent ?: "# Aucune propriété spécifique FOD exportée dans la session A.\n"
            )
        )

        // 4. Liste des fichiers/libs appelés dans A mais absents/non chargés dans B
        val missingFileItems = items.filter { it.subject.startsWith("Non appelé") }
        val filesList = buildString {
            appendLine("# Fichiers appelés dans la chaîne Live de A mais jamais appelés/chargés dans B (${missingFileItems.size})")
            missingFileItems.forEach { itDiff ->
                appendLine("- ${itDiff.subject.removePrefix("Non appelé / absent dans B : ")} -> ${itDiff.valueInA}")
            }
        }
        patches.add(
            LiveGeneratedPatch(
                id = "diff_live_files",
                fileName = "diff_fichiers_a_porter_et_sources.txt",
                title = "Fichiers appelés en Live dans A manquants dans B (${missingFileItems.size})",
                kind = "Inventaire d'exécution",
                targetPathHint = "reference_session_A/05_code_source_reconstruit/",
                description = "Liste exacte des bibliothèques, overlays et configs appelés en direct dans A et absents de B.",
                codeContent = filesList
            )
        )

        return patches
    }
}

package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Archive
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.CompareArrows
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.PlaylistAddCheck
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.ComparisonReport
import com.example.model.DiffCategory
import com.example.model.FodSnapshot
import com.example.model.GeneratedPatchArtifact
import com.example.model.GsiBlockerVerdict
import com.example.model.SystemLayer
import com.example.ui.components.StatusPillBadge
import com.example.ui.components.severityColor
import com.example.ui.theme.AmberWarning
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyanBiometric
import com.example.ui.theme.EmeraldVerified

@Composable
fun ComparatorScreen(
    snapshots: List<FodSnapshot>,
    selectedAId: String?,
    selectedBId: String?,
    report: ComparisonReport?,
    isExporting: Boolean = false,
    onSelectSnapshots: (String?, String?) -> Unit,
    onRunComparison: () -> Unit,
    onExportComparisonZip: () -> Unit = {},
    onShareComparisonZip: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    var selectedCategory by rememberSaveable { mutableStateOf<DiffCategory?>(null) }
    var selectedLayer by rememberSaveable { mutableStateOf<SystemLayer?>(null) }
    var showFullImplementationPlan by rememberSaveable { mutableStateOf(false) }
    var expandedVerdictId by rememberSaveable { mutableStateOf<String?>(null) }
    var expandedPatchId by rememberSaveable { mutableStateOf<String?>(null) }
    var copiedPatchId by remember { mutableStateOf<String?>(null) }
    var planCopied by remember { mutableStateOf(false) }

    val clipboardManager = LocalClipboardManager.current

    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            modifier = Modifier
                .widthIn(max = 840.dp)
                .fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // ── SÉLECTEUR DE CAPTURES A vs B ──────────────────────────────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            text = "Comparateur ROM d'origine vs GSI",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "Compare deux captures (locales ou dézippées via l'Importateur) dans /sdcard/FOD Database/ pour isoler chaque blocage FOD, générer les patchs d'imitation 100 % et exporter le pack complet d'implémentation.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        SnapshotSelectorDropdown(
                            label = "Capture A (Référence — ex. ROM d'origine)",
                            snapshots = snapshots,
                            selectedId = selectedAId,
                            onSelect = { onSelectSnapshots(it, selectedBId) },
                            testTag = "selector_snapshot_a"
                        )

                        SnapshotSelectorDropdown(
                            label = "Capture B (Cible — ex. GSI / DSU Sideloader)",
                            snapshots = snapshots,
                            selectedId = selectedBId,
                            onSelect = { onSelectSnapshots(selectedAId, it) },
                            testTag = "selector_snapshot_b"
                        )

                        Button(
                            onClick = onRunComparison,
                            enabled = snapshots.size >= 2 && selectedAId != null && selectedBId != null && selectedAId != selectedBId,
                            modifier = Modifier
                                .fillMaxWidth()
                                .minimumInteractiveComponentSize()
                                .testTag("run_comparison_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = CyanBiometric,
                                contentColor = Color(0xFF051018)
                            )
                        ) {
                            Icon(Icons.Rounded.CompareArrows, contentDescription = null, modifier = Modifier.size(20.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("COMPARER LES DEUX CAPTURES")
                        }

                        if (snapshots.size < 2) {
                            Text(
                                text = "Il faut au moins 2 captures dans /sdcard/FOD Database/ (lancez une analyse ici et importez le .zip de l'autre ROM sur l'accueil).",
                                style = MaterialTheme.typography.bodySmall,
                                color = AmberWarning
                            )
                        }
                    }
                }
            }

            if (report != null) {
                // ── BILAN DIFFÉRENTIEL & EXPORT ZIP DU PACK DE COMPARAISON ───────────
                item {
                    Card(
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        border = BorderStroke(1.dp, CyanBiometric.copy(alpha = 0.45f))
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Text("Bilan différentiel & export du plan", style = MaterialTheme.typography.titleMedium)

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .horizontalScroll(rememberScrollState()),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                StatusPillBadge(label = "${report.criticalBlockersCount} critiques", color = CrimsonCritical)
                                StatusPillBadge(label = "${report.missingInBCount} absents dans B", color = AmberWarning)
                                StatusPillBadge(label = "${report.modifiedShaCount} SHA-256 modifiés", color = CyanBiometric)
                                StatusPillBadge(label = "${report.propertyDeltaCount} propriétés", color = EmeraldVerified)
                                StatusPillBadge(label = "${report.deepFindingsCount} analyses profondes", color = CyanBiometric)
                                StatusPillBadge(label = "${report.generatedPatches.size} patchs", color = EmeraldVerified)
                            }

                            Text(
                                text = "Exporte un pack .zip complet dans /sdcard/FOD Database/Exports/ contenant : RAPPORT_COMPARAISON_COMPLET.md, PLAN_IMPLEMENTATION_FOD.md, comparison_data.json, patchs_proposes/* (.te, .prop, .xml, .rc), les fichiers non secrets de référence à porter et leur quasi-code source.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Button(
                                    onClick = onExportComparisonZip,
                                    enabled = !isExporting,
                                    modifier = Modifier
                                        .weight(1f)
                                        .minimumInteractiveComponentSize()
                                        .testTag("export_comparison_zip_button"),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = CyanBiometric,
                                        contentColor = Color(0xFF051018)
                                    )
                                ) {
                                    Icon(Icons.Rounded.Archive, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(8.dp))
                                    Text(
                                        text = if (isExporting) "Exportation..." else "EXPORTER RAPPORT & PLAN (.ZIP)",
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                                OutlinedButton(
                                    onClick = onShareComparisonZip,
                                    enabled = !isExporting,
                                    modifier = Modifier
                                        .minimumInteractiveComponentSize()
                                        .testTag("share_comparison_zip_button")
                                ) {
                                    Icon(
                                        Icons.Rounded.Share,
                                        contentDescription = "Partager le pack de comparaison .zip",
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(Modifier.width(6.dp))
                                    Text("Partager")
                                }
                            }

                            report.exportedZipPath?.let { exportedPath ->
                                Surface(
                                    shape = MaterialTheme.shapes.small,
                                    color = EmeraldVerified.copy(alpha = 0.12f),
                                    border = BorderStroke(1.dp, EmeraldVerified.copy(alpha = 0.4f))
                                ) {
                                    Text(
                                        text = "Archive générée : $exportedPath",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = EmeraldVerified,
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(10.dp)
                                    )
                                }
                            }
                        }
                    }
                }

                // ── RÉSUMÉ CAUSAL : POURQUOI LE FOD ÉCHOUE SUR LE GSI ────────────────
                if (report.gsiFailureSummary.isNotBlank() || report.layerVerdicts.isNotEmpty()) {
                    item {
                        val headerColor = if (report.criticalBlockersCount > 0) CrimsonCritical else AmberWarning
                        Card(
                            shape = MaterialTheme.shapes.medium,
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                            border = BorderStroke(1.dp, headerColor.copy(alpha = 0.55f))
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Icon(
                                        Icons.Rounded.WarningAmber,
                                        contentDescription = null,
                                        tint = headerColor
                                    )
                                    Text(
                                        text = "Pourquoi le FOD échoue sur le GSI sideloadé",
                                        style = MaterialTheme.typography.titleMedium,
                                        color = headerColor
                                    )
                                }

                                if (report.gsiFailureSummary.isNotBlank()) {
                                    Surface(
                                        shape = MaterialTheme.shapes.small,
                                        color = MaterialTheme.colorScheme.background
                                    ) {
                                        Text(
                                            text = report.gsiFailureSummary,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurface,
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(12.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }

                    if (report.layerVerdicts.isNotEmpty()) {
                        item {
                            Text(
                                text = "Verdict causal par couche système (8 couches)",
                                style = MaterialTheme.typography.titleSmall
                            )
                        }
                        items(report.layerVerdicts, key = { it.id }) { verdict ->
                            LayerVerdictCard(
                                verdict = verdict,
                                expanded = expandedVerdictId == verdict.id,
                                onToggleExpand = {
                                    expandedVerdictId = if (expandedVerdictId == verdict.id) null else verdict.id
                                }
                            )
                        }
                    }
                }

                // ── ACTIONS PRIORITAIRES POUR LE PORTAGE FOD ──────────────────────────
                if (report.portingChecklistFr.isNotEmpty()) {
                    item {
                        Card(
                            shape = MaterialTheme.shapes.medium,
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                            border = BorderStroke(1.dp, EmeraldVerified.copy(alpha = 0.45f))
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Icon(Icons.Rounded.PlaylistAddCheck, contentDescription = null, tint = EmeraldVerified)
                                    Text("Actions prioritaires pour le portage FOD", style = MaterialTheme.typography.titleSmall)
                                }
                                report.portingChecklistFr.take(24).forEachIndexed { idx, action ->
                                    Text(
                                        text = "${idx + 1}. $action",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            }
                        }
                    }
                }

                // ── PLAN D'IMPLÉMENTATION & PATCHS D'IMITATION 100 % ─────────────────
                if (report.generatedPatches.isNotEmpty() || report.implementationPlanMarkdown.isNotBlank()) {
                    item {
                        Card(
                            shape = MaterialTheme.shapes.medium,
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                            border = BorderStroke(1.dp, EmeraldVerified.copy(alpha = 0.5f))
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Icon(Icons.Rounded.Build, contentDescription = null, tint = EmeraldVerified)
                                    Text(
                                        text = "Plan d'implémentation & Patchs d'imitation (100 %)",
                                        style = MaterialTheme.typography.titleMedium
                                    )
                                }
                                Text(
                                    text = "Correctifs générés factuellement à partir de la capture A pour reproduire le comportement FOD exact sur le GSI B.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )

                                if (report.implementationPlanMarkdown.isNotBlank()) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        OutlinedButton(
                                            onClick = { showFullImplementationPlan = !showFullImplementationPlan },
                                            modifier = Modifier
                                                .weight(1f)
                                                .minimumInteractiveComponentSize()
                                                .testTag("toggle_implementation_plan_button")
                                        ) {
                                            Icon(
                                                Icons.Rounded.Description,
                                                contentDescription = null,
                                                modifier = Modifier.size(18.dp)
                                            )
                                            Spacer(Modifier.width(6.dp))
                                            Text(
                                                if (showFullImplementationPlan) "Masquer PLAN_IMPLEMENTATION_FOD.md"
                                                else "Afficher PLAN_IMPLEMENTATION_FOD.md"
                                            )
                                        }
                                        OutlinedButton(
                                            onClick = {
                                                clipboardManager.setText(AnnotatedString(report.implementationPlanMarkdown))
                                                planCopied = true
                                            },
                                            modifier = Modifier
                                                .minimumInteractiveComponentSize()
                                                .testTag("copy_implementation_plan_button")
                                        ) {
                                            Icon(
                                                if (planCopied) Icons.Rounded.Check else Icons.Rounded.ContentCopy,
                                                contentDescription = "Copier le plan d'implémentation",
                                                modifier = Modifier.size(16.dp)
                                            )
                                            Spacer(Modifier.width(4.dp))
                                            Text(if (planCopied) "Copié" else "Copier")
                                        }
                                    }

                                    AnimatedVisibility(visible = showFullImplementationPlan) {
                                        Surface(
                                            shape = MaterialTheme.shapes.small,
                                            color = MaterialTheme.colorScheme.background,
                                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                                        ) {
                                            Box(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .horizontalScroll(rememberScrollState())
                                                    .padding(12.dp)
                                            ) {
                                                Text(
                                                    text = report.implementationPlanMarkdown,
                                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                                    color = MaterialTheme.colorScheme.onSurface
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    items(report.generatedPatches, key = { it.id }) { patch ->
                        GeneratedPatchCard(
                            patch = patch,
                            expanded = expandedPatchId == patch.id,
                            isCopied = copiedPatchId == patch.id,
                            onToggleExpand = {
                                expandedPatchId = if (expandedPatchId == patch.id) null else patch.id
                            },
                            onCopy = {
                                clipboardManager.setText(AnnotatedString(patch.codeContent))
                                copiedPatchId = patch.id
                            }
                        )
                    }
                }

                // ── FILTRES DES ÉCARTS DÉTAILLÉS (CATÉGORIE & COUCHE) ─────────────────
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            text = "Écarts détaillés A vs B (${report.diffs.size})",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            FilterChip(
                                selected = selectedCategory == null,
                                onClick = { selectedCategory = null },
                                label = { Text("Toutes catégories (${report.diffs.size})") },
                                modifier = Modifier.testTag("filter_cat_all")
                            )
                            DiffCategory.entries.forEach { cat ->
                                val cnt = report.diffs.count { it.category == cat }
                                if (cnt > 0) {
                                    FilterChip(
                                        selected = selectedCategory == cat,
                                        onClick = { selectedCategory = if (selectedCategory == cat) null else cat },
                                        label = { Text("${cat.labelFr} ($cnt)") },
                                        modifier = Modifier.testTag("filter_cat_${cat.name}")
                                    )
                                }
                            }
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            FilterChip(
                                selected = selectedLayer == null,
                                onClick = { selectedLayer = null },
                                label = { Text("Toutes couches") },
                                modifier = Modifier.testTag("filter_layer_all")
                            )
                            SystemLayer.entries.forEach { layer ->
                                val cnt = report.diffs.count {
                                    it.layer == layer && (selectedCategory == null || it.category == selectedCategory)
                                }
                                if (cnt > 0) {
                                    FilterChip(
                                        selected = selectedLayer == layer,
                                        onClick = { selectedLayer = if (selectedLayer == layer) null else layer },
                                        label = { Text("${layer.labelFr} ($cnt)") },
                                        modifier = Modifier.testTag("filter_layer_${layer.name}")
                                    )
                                }
                            }
                        }
                    }
                }

                val filteredDiffs = report.diffs.filter { diff ->
                    (selectedCategory == null || diff.category == selectedCategory) &&
                        (selectedLayer == null || diff.layer == selectedLayer)
                }
                items(filteredDiffs, key = { it.id }) { diff ->
                    val accent = severityColor(diff.severity)
                    Card(
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        border = BorderStroke(1.dp, accent.copy(alpha = 0.45f))
                    ) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = diff.keyOrPath,
                                    style = MaterialTheme.typography.labelMedium,
                                    color = CyanBiometric,
                                    modifier = Modifier.weight(1f)
                                )
                                StatusPillBadge(label = diff.severity.labelFr, color = accent)
                            }
                            Text(
                                text = "${diff.layer.labelFr} • ${diff.category.labelFr}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Surface(
                                shape = MaterialTheme.shapes.small,
                                color = MaterialTheme.colorScheme.background
                            ) {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(8.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Text("A : ${diff.valueA}", style = MaterialTheme.typography.labelSmall, color = EmeraldVerified)
                                    Text("B : ${diff.valueB}", style = MaterialTheme.typography.labelSmall, color = AmberWarning)
                                }
                            }
                            Text(
                                text = diff.portingNote,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LayerVerdictCard(
    verdict: GsiBlockerVerdict,
    expanded: Boolean,
    onToggleExpand: () -> Unit
) {
    val accent = if (verdict.isBlocking) CrimsonCritical else EmeraldVerified
    Card(
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, accent.copy(alpha = 0.5f)),
        modifier = Modifier.testTag("verdict_card_${verdict.id}")
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = verdict.layer.labelFr,
                        style = MaterialTheme.typography.labelSmall,
                        color = CyanBiometric
                    )
                    Text(
                        text = verdict.title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    StatusPillBadge(
                        label = if (verdict.isBlocking) "BLOQUANT" else "OK / PROCHE",
                        color = accent
                    )
                    IconButton(
                        onClick = onToggleExpand,
                        modifier = Modifier
                            .minimumInteractiveComponentSize()
                            .testTag("toggle_verdict_${verdict.id}")
                    ) {
                        Icon(
                            imageVector = if (expanded) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                            contentDescription = if (expanded) "Réduire le verdict" else "Développer le verdict"
                        )
                    }
                }
            }

            Text(
                text = "Cause : ${verdict.rootCause}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface
            )

            Surface(
                shape = MaterialTheme.shapes.small,
                color = EmeraldVerified.copy(alpha = 0.1f),
                border = BorderStroke(1.dp, EmeraldVerified.copy(alpha = 0.3f))
            ) {
                Text(
                    text = "Imitation 100 % : ${verdict.imitationSolution}",
                    style = MaterialTheme.typography.bodySmall,
                    color = EmeraldVerified,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(10.dp)
                )
            }

            AnimatedVisibility(visible = expanded) {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = MaterialTheme.colorScheme.background
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(10.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text("Statut A : ${verdict.statusInA}", style = MaterialTheme.typography.labelSmall, color = EmeraldVerified)
                        Text("Statut B : ${verdict.statusInB}", style = MaterialTheme.typography.labelSmall, color = AmberWarning)
                        Text("Preuve A : ${verdict.evidenceA}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text("Preuve B : ${verdict.evidenceB}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

@Composable
private fun GeneratedPatchCard(
    patch: GeneratedPatchArtifact,
    expanded: Boolean,
    isCopied: Boolean,
    onToggleExpand: () -> Unit,
    onCopy: () -> Unit
) {
    Card(
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, CyanBiometric.copy(alpha = 0.4f)),
        modifier = Modifier.testTag("patch_card_${patch.id}")
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = patch.fileName,
                        style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace),
                        color = CyanBiometric
                    )
                    Text(
                        text = patch.title,
                        style = MaterialTheme.typography.titleSmall
                    )
                }
                StatusPillBadge(label = patch.kind, color = EmeraldVerified)
            }

            Text(
                text = "Cible suggérée : ${patch.targetPathHint}",
                style = MaterialTheme.typography.labelSmall,
                color = AmberWarning
            )
            Text(
                text = patch.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(
                    onClick = onToggleExpand,
                    modifier = Modifier
                        .minimumInteractiveComponentSize()
                        .testTag("toggle_patch_${patch.id}")
                ) {
                    Icon(Icons.Rounded.Code, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(if (expanded) "Masquer le patch" else "Afficher le patch")
                }

                OutlinedButton(
                    onClick = onCopy,
                    modifier = Modifier
                        .minimumInteractiveComponentSize()
                        .testTag("copy_patch_${patch.id}")
                ) {
                    Icon(
                        if (isCopied) Icons.Rounded.Check else Icons.Rounded.ContentCopy,
                        contentDescription = "Copier ${patch.fileName}",
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(if (isCopied) "Copié" else "Copier")
                }
            }

            AnimatedVisibility(visible = expanded) {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = MaterialTheme.colorScheme.background,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState())
                            .padding(12.dp)
                    ) {
                        Text(
                            text = patch.codeContent,
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SnapshotSelectorDropdown(
    label: String,
    snapshots: List<FodSnapshot>,
    selectedId: String?,
    onSelect: (String) -> Unit,
    testTag: String
) {
    var expanded by remember { mutableStateOf(false) }
    val current = snapshots.find { it.metadata.id == selectedId }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = !expanded }
    ) {
        OutlinedTextField(
            value = current?.metadata?.displayName ?: "Sélectionner une capture...",
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                .testTag(testTag)
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            snapshots.forEach { snap ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(snap.metadata.displayName, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "${snap.metadata.id} • ${snap.artifacts.size} artefacts",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    },
                    onClick = {
                        onSelect(snap.metadata.id)
                        expanded = false
                    }
                )
            }
        }
    }
}

package com.example.ui.screens

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
import androidx.compose.material.icons.rounded.CompareArrows
import androidx.compose.material.icons.rounded.PlaylistAddCheck
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.model.ComparisonReport
import com.example.model.DiffCategory
import com.example.model.FodSnapshot
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
    onSelectSnapshots: (String?, String?) -> Unit,
    onRunComparison: () -> Unit,
    modifier: Modifier = Modifier
) {
    var selectedCategory by rememberSaveable { mutableStateOf<DiffCategory?>(null) }

    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            modifier = Modifier
                .widthIn(max = 820.dp)
                .fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
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
                            text = "Compare deux captures (locales ou dézippées via l'Importateur) dans /sdcard/FOD Database/ pour isoler chaque fichier, bibliothèque ELF, propriété, RRO ou règle SELinux manquante.",
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
                            label = "Capture B (Cible — ex. GSI DSU)",
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
                item {
                    Card(
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        border = BorderStroke(1.dp, CyanBiometric.copy(alpha = 0.45f))
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Text("Bilan différentiel factuel", style = MaterialTheme.typography.titleMedium)
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
                            }
                        }
                    }
                }

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
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Rounded.PlaylistAddCheck, contentDescription = null, tint = EmeraldVerified)
                                    Text("Actions prioritaires pour le portage FOD", style = MaterialTheme.typography.titleSmall)
                                }
                                report.portingChecklistFr.take(20).forEachIndexed { idx, action ->
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

                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        FilterChip(
                            selected = selectedCategory == null,
                            onClick = { selectedCategory = null },
                            label = { Text("Tous (${report.diffs.size})") }
                        )
                        DiffCategory.entries.forEach { cat ->
                            val cnt = report.diffs.count { it.category == cat }
                            if (cnt > 0) {
                                FilterChip(
                                    selected = selectedCategory == cat,
                                    onClick = { selectedCategory = if (selectedCategory == cat) null else cat },
                                    label = { Text("${cat.labelFr} ($cnt)") }
                                )
                            }
                        }
                    }
                }

                val filteredDiffs = report.diffs.filter { selectedCategory == null || it.category == selectedCategory }
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
                                Column(modifier = Modifier.fillMaxWidth().padding(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
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

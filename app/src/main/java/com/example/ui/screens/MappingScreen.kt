package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountTree
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.model.DiscoveredArtifact
import com.example.model.FodSnapshot
import com.example.model.SystemLayer
import com.example.ui.components.StatusPillBadge
import com.example.ui.components.nodeStatusColor
import com.example.ui.theme.AmberWarning
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyanBiometric
import com.example.ui.theme.EmeraldVerified

@Composable
fun MappingScreen(
    snapshot: FodSnapshot?,
    modifier: Modifier = Modifier
) {
    if (snapshot == null) {
        Box(
            modifier = modifier
                .fillMaxSize()
                .padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Icon(Icons.Rounded.AccountTree, contentDescription = null, tint = CyanBiometric)
                Text("Cartographie FOD indisponible", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "Lancez ou importez une capture pour visualiser l'architecture technique et les artefacts découverts.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        return
    }

    var searchQuery by rememberSaveable { mutableStateOf("") }
    var selectedLayer by rememberSaveable { mutableStateOf<SystemLayer?>(null) }
    var expandedArtifactId by rememberSaveable { mutableStateOf<String?>(null) }

    val filteredArtifacts = remember(snapshot.artifacts, searchQuery, selectedLayer) {
        snapshot.artifacts.filter { art ->
            val matchLayer = selectedLayer == null || art.layer == selectedLayer
            val q = searchQuery.trim().lowercase()
            val matchQuery = q.isEmpty() ||
                art.path.lowercase().contains(q) ||
                art.kind.lowercase().contains(q) ||
                art.summary.lowercase().contains(q) ||
                art.sha256.lowercase().contains(q)
            matchLayer && matchQuery
        }
    }

    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            modifier = Modifier
                .widthIn(max = 820.dp)
                .fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ── GRAPHE VISUEL D'ARCHITECTURE FOD ─────────────────────────────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text(
                            text = "Architecture causale du FOD (${snapshot.metadata.romType.labelFr})",
                            style = MaterialTheme.typography.titleMedium
                        )
                        val nodeColors = snapshot.nodes.associate { it.id to nodeStatusColor(it.status) }
                        Canvas(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(185.dp)
                        ) {
                            val w = size.width
                            val h = size.height
                            val positions = mapOf(
                                "node_framework" to Offset(w * 0.50f, h * 0.14f),
                                "node_hal" to Offset(w * 0.24f, h * 0.42f),
                                "node_display" to Offset(w * 0.54f, h * 0.42f),
                                "node_touch" to Offset(w * 0.82f, h * 0.42f),
                                "node_vendor" to Offset(w * 0.24f, h * 0.72f),
                                "node_selinux" to Offset(w * 0.54f, h * 0.72f),
                                "node_kernel" to Offset(w * 0.82f, h * 0.72f),
                                "node_dt" to Offset(w * 0.50f, h * 0.92f)
                            )
                            val brokenDash = PathEffect.dashPathEffect(floatArrayOf(10f, 8f), 0f)
                            snapshot.edges.forEach { edge ->
                                val p1 = positions[edge.fromId]
                                val p2 = positions[edge.toId]
                                if (p1 != null && p2 != null) {
                                    drawLine(
                                        color = if (edge.isBroken) CrimsonCritical else CyanBiometric.copy(alpha = 0.7f),
                                        start = p1,
                                        end = p2,
                                        strokeWidth = if (edge.isBroken) 3.5f else 2.5f,
                                        pathEffect = if (edge.isBroken) brokenDash else null
                                    )
                                }
                            }
                            positions.forEach { (id, center) ->
                                val c = nodeColors[id] ?: CyanBiometric
                                drawCircle(color = c.copy(alpha = 0.25f), radius = 16.dp.toPx(), center = center)
                                drawCircle(color = c, radius = 9.dp.toPx(), center = center)
                            }
                        }

                        // Légende des liaisons inter-couches
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            snapshot.edges.forEach { edge ->
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "${edge.fromId.removePrefix("node_")} → ${edge.toId.removePrefix("node_")} (${edge.relation})",
                                        style = MaterialTheme.typography.labelSmall,
                                        modifier = Modifier.weight(1f)
                                    )
                                    StatusPillBadge(
                                        label = if (edge.isBroken) "RUPTURE" else "LIEN OK",
                                        color = if (edge.isBroken) CrimsonCritical else EmeraldVerified
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // ── FILTRES & RECHERCHE D'ARTEFACTS ─────────────────────────────────────────
            item {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("mapping_search_field"),
                    leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
                    label = { Text("Filtrer chemin, symbole, SHA-256 ou type...") },
                    singleLine = true
                )
            }

            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChip(
                        selected = selectedLayer == null,
                        onClick = { selectedLayer = null },
                        label = { Text("Toutes (${snapshot.artifacts.size})") }
                    )
                    SystemLayer.entries.forEach { layer ->
                        val count = snapshot.artifacts.count { it.layer == layer }
                        if (count > 0) {
                            FilterChip(
                                selected = selectedLayer == layer,
                                onClick = { selectedLayer = if (selectedLayer == layer) null else layer },
                                label = { Text("${layer.labelFr} ($count)") }
                            )
                        }
                    }
                }
            }

            items(filteredArtifacts, key = { it.id }) { artifact ->
                ArtifactDetailCard(
                    artifact = artifact,
                    expanded = expandedArtifactId == artifact.id,
                    onToggle = {
                        expandedArtifactId = if (expandedArtifactId == artifact.id) null else artifact.id
                    }
                )
            }
        }
    }
}

@Composable
private fun ArtifactDetailCard(
    artifact: DiscoveredArtifact,
    expanded: Boolean,
    onToggle: () -> Unit
) {
    val hasMissingElf = (artifact.elfAnalysis?.missingLibraries?.isNotEmpty()) == true
    val borderColor = when {
        hasMissingElf -> CrimsonCritical.copy(alpha = 0.6f)
        artifact.isOemPatch -> AmberWarning.copy(alpha = 0.5f)
        else -> MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
    }

    Card(
        onClick = onToggle,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("artifact_card_${artifact.id}"),
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, borderColor)
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = artifact.path,
                        style = MaterialTheme.typography.labelMedium,
                        color = CyanBiometric
                    )
                    Text(
                        text = "${artifact.kind} • ${artifact.layer.labelFr}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Icon(
                    imageVector = if (expanded) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                    contentDescription = if (expanded) "Réduire" else "Développer"
                )
            }

            Text(
                text = artifact.summary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface
            )

            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                if (artifact.isOemPatch) {
                    StatusPillBadge(label = "Spécifique constructeur", color = AmberWarning)
                }
                if (hasMissingElf) {
                    StatusPillBadge(label = "DT_NEEDED manquante", color = CrimsonCritical)
                }
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
                        Text("SHA-256 : ${artifact.sha256}", style = MaterialTheme.typography.labelSmall)
                        Text("Permissions : ${artifact.permissions} | SELinux : ${artifact.seLinuxContext}", style = MaterialTheme.typography.labelSmall)

                        artifact.elfAnalysis?.let { elf ->
                            Text("ELF : ${elf.machine} | SONAME: ${elf.soName ?: "-"}", style = MaterialTheme.typography.labelSmall, color = CyanBiometric)
                            if (elf.neededLibraries.isNotEmpty()) {
                                Text("DT_NEEDED : ${elf.neededLibraries.joinToString(", ")}", style = MaterialTheme.typography.labelSmall)
                            }
                            if (elf.missingLibraries.isNotEmpty()) {
                                Text("MANQUANTES : ${elf.missingLibraries.joinToString(", ")}", style = MaterialTheme.typography.labelSmall, color = CrimsonCritical)
                            }
                            if (elf.fodSymbols.isNotEmpty()) {
                                Text("Symboles FOD : ${elf.fodSymbols.take(20).joinToString(", ")}", style = MaterialTheme.typography.labelSmall, color = EmeraldVerified)
                            }
                        }

                        artifact.dexRroAnalysis?.let { dr ->
                            dr.packageName?.let { Text("Package : $it", style = MaterialTheme.typography.labelSmall, color = CyanBiometric) }
                            dr.rroTargetPackage?.let { Text("RRO cible : $it (priorité ${dr.rroPriority ?: "?"})", style = MaterialTheme.typography.labelSmall, color = AmberWarning) }
                            if (dr.matchedClasses.isNotEmpty()) {
                                Text("Classes DEX : ${dr.matchedClasses.take(15).joinToString("\n")}", style = MaterialTheme.typography.labelSmall)
                            }
                            if (dr.matchedConfigKeys.isNotEmpty()) {
                                Text("Clés config/ressources : ${dr.matchedConfigKeys.take(20).joinToString(", ")}", style = MaterialTheme.typography.labelSmall, color = EmeraldVerified)
                            }
                        }

                        if (artifact.rawExcerpt.isNotBlank()) {
                            Text(
                                text = artifact.rawExcerpt.take(900),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

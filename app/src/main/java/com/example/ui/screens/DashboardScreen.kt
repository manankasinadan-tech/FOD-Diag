package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Archive
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.model.FodSnapshot
import com.example.model.SeverityLevel
import com.example.ui.components.AnomalyCard
import com.example.ui.components.ScoreGaugeRing
import com.example.ui.components.StatusPillBadge
import com.example.ui.components.nodeStatusColor
import com.example.ui.theme.AmberWarning
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyanBiometric
import com.example.ui.theme.EmeraldVerified

@Composable
fun DashboardScreen(
    snapshot: FodSnapshot?,
    isExporting: Boolean,
    onExportZip: () -> Unit,
    onShareZip: () -> Unit,
    onGoToHome: () -> Unit,
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
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = Icons.Rounded.Fingerprint,
                    contentDescription = null,
                    tint = CyanBiometric,
                    modifier = Modifier.size(52.dp)
                )
                Text("Aucun tableau de bord actif", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "Lancez une analyse FOD depuis l'accueil ou importez une archive .zip pour afficher son tableau de bord complet.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Button(
                    onClick = onGoToHome,
                    modifier = Modifier
                        .minimumInteractiveComponentSize()
                        .testTag("dashboard_back_home_button")
                ) {
                    Text("Aller à l'accueil")
                }
            }
        }
        return
    }

    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    val tabs = listOf("Diagnostic", "Rapport complet", "Propriétés & SELinux", "Sécurité")
    val meta = snapshot.metadata

    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            modifier = Modifier
                .widthIn(max = 780.dp)
                .fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // ── EN-TÊTE TABLEAU DE BORD & EXPORT .ZIP ───────────────────────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            ScoreGaugeRing(score = meta.completenessScore)
                            Column(
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = meta.displayName,
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "Android ${meta.androidVersion} (API ${meta.sdkInt}) • ${meta.boardPlatform}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    text = "Empreinte : ${meta.buildFingerprint}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = CyanBiometric
                                )
                            }
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            StatusPillBadge(
                                label = "${snapshot.artifacts.size} artefacts",
                                color = CyanBiometric
                            )
                            StatusPillBadge(
                                label = "${snapshot.anomalies.count { it.severity == SeverityLevel.CRITIQUE }} critiques",
                                color = if (snapshot.anomalies.any { it.severity == SeverityLevel.CRITIQUE }) CrimsonCritical else EmeraldVerified
                            )
                            StatusPillBadge(
                                label = "SELinux: ${meta.seLinuxMode}",
                                color = AmberWarning
                            )
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Button(
                                onClick = onExportZip,
                                enabled = !isExporting,
                                modifier = Modifier
                                    .weight(1f)
                                    .minimumInteractiveComponentSize()
                                    .testTag("export_zip_button"),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = CyanBiometric,
                                    contentColor = Color(0xFF051018)
                                )
                            ) {
                                Icon(Icons.Rounded.Archive, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(id = R.string.cta_export_zip))
                            }
                            OutlinedButton(
                                onClick = onShareZip,
                                enabled = !isExporting,
                                modifier = Modifier
                                    .minimumInteractiveComponentSize()
                                    .testTag("share_zip_button")
                            ) {
                                Icon(Icons.Rounded.Share, contentDescription = "Partager le .zip", modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Partager")
                            }
                        }
                    }
                }
            }

            // ── ONGLETS DU TABLEAU DE BORD ──────────────────────────────────────────────
            item {
                ScrollableTabRow(
                    selectedTabIndex = selectedTab,
                    containerColor = MaterialTheme.colorScheme.surface,
                    edgePadding = 8.dp
                ) {
                    tabs.forEachIndexed { idx, title ->
                        Tab(
                            selected = selectedTab == idx,
                            onClick = { selectedTab = idx },
                            text = { Text(title) },
                            modifier = Modifier.testTag("dashboard_tab_$idx")
                        )
                    }
                }
            }

            when (selectedTab) {
                0 -> {
                    item {
                        Text("État des couches FOD", style = MaterialTheme.typography.titleMedium)
                    }
                    items(snapshot.nodes, key = { it.id }) { node ->
                        val color = nodeStatusColor(node.status)
                        Card(
                            shape = MaterialTheme.shapes.medium,
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                            border = BorderStroke(1.dp, color.copy(alpha = 0.35f))
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text(node.label, style = MaterialTheme.typography.titleSmall)
                                    Text(
                                        node.details,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                StatusPillBadge(label = node.status.labelFr, color = color)
                            }
                        }
                    }
                    item {
                        Text(
                            "Anomalies & diagnostics factuels (${snapshot.anomalies.size})",
                            style = MaterialTheme.typography.titleMedium
                        )
                    }
                    if (snapshot.anomalies.isEmpty()) {
                        item {
                            Card(
                                shape = MaterialTheme.shapes.medium,
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                            ) {
                                Text(
                                    "Aucune anomalie critique relevée : la chaîne FOD semble cohérente sur cet environnement.",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = EmeraldVerified,
                                    modifier = Modifier.padding(16.dp)
                                )
                            }
                        }
                    } else {
                        items(snapshot.anomalies, key = { it.id }) { anomaly ->
                            AnomalyCard(anomaly = anomaly)
                        }
                    }
                }

                1 -> {
                    item {
                        Card(
                            shape = MaterialTheme.shapes.medium,
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                        ) {
                            Column(
                                modifier = Modifier.padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Rounded.Description, contentDescription = null, tint = CyanBiometric)
                                    Text("RAPPORT_COMPLET_FOD.md", style = MaterialTheme.typography.titleSmall)
                                }
                                Text(
                                    text = "Enregistré dans : ${meta.snapshotDirPath}/RAPPORT_COMPLET_FOD.md",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = EmeraldVerified
                                )
                                Surface(
                                    shape = MaterialTheme.shapes.small,
                                    color = MaterialTheme.colorScheme.background
                                ) {
                                    Text(
                                        text = snapshot.reportMarkdown.ifBlank { "Rapport vide" },
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.onSurface,
                                        modifier = Modifier.padding(12.dp)
                                    )
                                }
                            }
                        }
                    }
                }

                2 -> {
                    item {
                        Text("Propriétés FOD / Affichage / Tactile (${snapshot.properties.size})", style = MaterialTheme.typography.titleMedium)
                    }
                    items(snapshot.properties.entries.toList(), key = { it.key }) { (k, v) ->
                        Surface(
                            shape = MaterialTheme.shapes.small,
                            color = MaterialTheme.colorScheme.surface,
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                        ) {
                            Column(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
                                Text(k, style = MaterialTheme.typography.labelMedium, color = CyanBiometric)
                                Text(v, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
                            }
                        }
                    }
                    item {
                        Text("Entrées SELinux & AVC (${snapshot.selinuxFindings.size})", style = MaterialTheme.typography.titleMedium)
                    }
                    items(snapshot.selinuxFindings.take(60)) { finding ->
                        Surface(
                            shape = MaterialTheme.shapes.small,
                            color = MaterialTheme.colorScheme.surface
                        ) {
                            Text(
                                text = "[${finding.sourceType}] ${finding.rawLine}",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (finding.sourceType == "AVC_DENIED") CrimsonCritical else MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.fillMaxWidth().padding(10.dp)
                            )
                        }
                    }
                }

                3 -> {
                    item {
                        Card(
                            shape = MaterialTheme.shapes.medium,
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                            border = BorderStroke(1.dp, EmeraldVerified.copy(alpha = 0.45f))
                        ) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Rounded.Lock, contentDescription = null, tint = EmeraldVerified)
                                    Text("Protection des secrets & gabarits biométriques", style = MaterialTheme.typography.titleSmall)
                                }
                                Text(
                                    "Aucune lecture ni exportation des gabarits d'empreintes (/fpdata/), clés TEE ou stockage protégé par le matériel.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                snapshot.biometricExclusions.forEach { excl ->
                                    Text("• $excl", style = MaterialTheme.typography.labelSmall, color = EmeraldVerified)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

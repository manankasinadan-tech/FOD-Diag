package com.example.livefod

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Archive
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.CompareArrows
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Share
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import com.example.ui.components.StatusPillBadge
import com.example.ui.theme.AmberWarning
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyanBiometric
import com.example.ui.theme.EmeraldVerified

@Composable
fun liveOutcomeColor(outcome: LiveOutcome): Color = when (outcome) {
    LiveOutcome.REACTION_DETECTEE -> EmeraldVerified
    LiveOutcome.TRANSITION_ETAT -> CyanBiometric
    LiveOutcome.SILENCE_RADIO -> AmberWarning
    LiveOutcome.ERREUR_EXPLICITE -> CrimsonCritical
    LiveOutcome.INFO_TECHNIQUE -> Color(0xFF94A3B8)
}

@Composable
fun LiveMechanismSection(session: LiveFodSession) {
    val mech = session.mechanism
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            shape = MaterialTheme.shapes.medium,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, CyanBiometric.copy(alpha = 0.45f))
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Mécanisme FOD détecté en direct", style = MaterialTheme.typography.titleMedium)
                Text(mech.enrollmentVerdict, style = MaterialTheme.typography.titleSmall, color = CyanBiometric)
                Text("Architecture : ${mech.primaryArchitecture}", style = MaterialTheme.typography.bodySmall)
                Text("Illumination : ${mech.displayIlluminationMethod}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("Tactile : ${mech.touchInteractionMethod}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (mech.errorSignatures.isNotEmpty()) {
                    Surface(shape = MaterialTheme.shapes.small, color = CrimsonCritical.copy(alpha = 0.12f)) {
                        Column(modifier = Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Erreurs capturées :", style = MaterialTheme.typography.labelMedium, color = CrimsonCritical)
                            mech.errorSignatures.forEach { err ->
                                Text("• $err", style = MaterialTheme.typography.labelSmall, color = CrimsonCritical)
                            }
                        }
                    }
                }
            }
        }

        Text("Chaîne d'interaction étape par étape", style = MaterialTheme.typography.titleSmall)
        mech.hops.forEach { hop ->
            val accent = liveOutcomeColor(hop.outcome)
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
                            text = "${hop.order}. ${hop.hopName}",
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.weight(1f)
                        )
                        StatusPillBadge(label = hop.outcome.labelFr, color = accent)
                    }
                    Text(hop.factualEvidence, style = MaterialTheme.typography.bodySmall)
                    if (hop.actorsObserved.isNotEmpty()) {
                        Text(
                            text = "Acteurs : ${hop.actorsObserved.joinToString(", ")}",
                            style = MaterialTheme.typography.labelSmall,
                            color = CyanBiometric
                        )
                    }
                    if (hop.filesAndNodesInvolved.isNotEmpty()) {
                        Text(
                            text = "Fichiers/Nœuds : ${hop.filesAndNodesInvolved.take(5).joinToString(", ")}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        val changedSysfs = session.sysfsTransitions.filter { it.hasChanged }
        if (changedSysfs.isNotEmpty()) {
            Card(
                shape = MaterialTheme.shapes.medium,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                border = BorderStroke(1.dp, EmeraldVerified.copy(alpha = 0.45f))
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Transitions Sysfs réelles (${changedSysfs.size})", style = MaterialTheme.typography.titleSmall, color = EmeraldVerified)
                    changedSysfs.forEach { t ->
                        Text(
                            text = "${t.path} : ${t.beforeValue} -> ${t.duringValues} -> ${t.afterValue}",
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace)
                        )
                    }
                }
            }
        }

        if (session.halProcesses.isNotEmpty()) {
            Text("Processus chaîne inspectés via /proc (${session.halProcesses.size})", style = MaterialTheme.typography.titleSmall)
            session.halProcesses.take(12).forEach { proc ->
                Card(
                    shape = MaterialTheme.shapes.medium,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("${proc.processName} (PID ${proc.pid} • UID ${proc.uid})", style = MaterialTheme.typography.labelMedium, color = CyanBiometric)
                        Text("SELinux : ${proc.seLinuxContext}", style = MaterialTheme.typography.labelSmall)
                        Text(
                            text = "${proc.mappedFiles.size} libs mappées • ${proc.openFds.size} descripteurs ouverts • ${proc.straceHighlights.size} traces strace",
                            style = MaterialTheme.typography.labelSmall,
                            color = EmeraldVerified
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun LiveTimelineSection(session: LiveFodSession) {
    var selectedSource by rememberSaveable { mutableStateOf<LiveEventSource?>(null) }
    var search by rememberSaveable { mutableStateOf("") }

    val filtered = remember(session.timelineEvents, selectedSource, search) {
        val q = search.trim().lowercase()
        session.timelineEvents.filter { ev ->
            (selectedSource == null || ev.source == selectedSource) &&
                (q.isEmpty() || ev.actor.lowercase().contains(q) || ev.summary.lowercase().contains(q) || ev.rawDetail.lowercase().contains(q))
        }.take(250)
    }

    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            label = { Text("Filtrer la chronologie brute (PID, HBM, avc, ioctl...)") },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("live_timeline_search")
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = selectedSource == null,
                onClick = { selectedSource = null },
                label = { Text("Tous (${session.timelineEvents.size})") }
            )
            LiveEventSource.entries.forEach { src ->
                val count = session.timelineEvents.count { it.source == src }
                if (count > 0) {
                    FilterChip(
                        selected = selectedSource == src,
                        onClick = { selectedSource = if (selectedSource == src) null else src },
                        label = { Text("${src.labelFr} ($count)") }
                    )
                }
            }
        }

        filtered.forEach { ev ->
            val accent = liveOutcomeColor(ev.outcome)
            Card(
                shape = MaterialTheme.shapes.small,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                border = BorderStroke(1.dp, accent.copy(alpha = 0.4f))
            ) {
                Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "${ev.relativeTimeLabel} • ${ev.source.labelFr} • ${ev.actor}",
                            style = MaterialTheme.typography.labelSmall,
                            color = CyanBiometric,
                            modifier = Modifier.weight(1f)
                        )
                        StatusPillBadge(label = ev.outcome.labelFr, color = accent)
                    }
                    Text(ev.summary, style = MaterialTheme.typography.bodySmall)
                    if (ev.rawDetail.isNotBlank() && ev.rawDetail != ev.summary) {
                        Text(
                            text = ev.rawDetail.take(360),
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun LiveFilesSourcesPatchesSection(
    session: LiveFodSession,
    onReadSubFile: (LiveFodSession, String) -> String
) {
    var mode by rememberSaveable { mutableIntStateOf(0) } // 0=Fichiers & Sources, 1=Patchs, 2=Logs bruts
    var expandedItemId by rememberSaveable { mutableStateOf<String?>(null) }
    var rawFilePreviewPath by rememberSaveable { mutableStateOf<String?>(null) }
    var copiedId by remember { mutableStateOf<String?>(null) }
    val clipboard = LocalClipboardManager.current

    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = mode == 0,
                onClick = { mode = 0 },
                label = { Text("Fichiers & Codes Sources (${session.extractedFiles.size})") },
                modifier = Modifier.testTag("live_subtab_sources")
            )
            FilterChip(
                selected = mode == 1,
                onClick = { mode = 1 },
                label = { Text("Patchs générés (${session.patches.size})") },
                modifier = Modifier.testTag("live_subtab_patches")
            )
            FilterChip(
                selected = mode == 2,
                onClick = { mode = 2 },
                label = { Text("Fichiers bruts disque (${session.rawFilesManifest.size})") },
                modifier = Modifier.testTag("live_subtab_raw")
            )
        }

        when (mode) {
            0 -> {
                session.extractedFiles.forEach { fileRec ->
                    val expanded = expandedItemId == fileRec.id
                    Card(
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                    ) {
                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(
                                text = fileRec.originalPath,
                                style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace),
                                color = CyanBiometric
                            )
                            Text(
                                text = "${fileRec.category} • ${fileRec.reasonInChain}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            fileRec.sourceCodeRelPath?.let {
                                Text("Code source : $it", style = MaterialTheme.typography.labelSmall, color = EmeraldVerified)
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                TextButton(
                                    onClick = { expandedItemId = if (expanded) null else fileRec.id },
                                    modifier = Modifier.minimumInteractiveComponentSize()
                                ) {
                                    Icon(Icons.Rounded.Code, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text(if (expanded) "Masquer code source" else "Voir code source")
                                }
                                OutlinedButton(
                                    onClick = {
                                        clipboard.setText(AnnotatedString(fileRec.reconstructedSourceCode.ifBlank { fileRec.rawPreview }))
                                        copiedId = fileRec.id
                                    },
                                    modifier = Modifier.minimumInteractiveComponentSize()
                                ) {
                                    Icon(if (copiedId == fileRec.id) Icons.Rounded.Check else Icons.Rounded.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text(if (copiedId == fileRec.id) "Copié" else "Copier")
                                }
                            }
                            AnimatedVisibility(visible = expanded) {
                                Surface(shape = MaterialTheme.shapes.small, color = MaterialTheme.colorScheme.background) {
                                    Box(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .horizontalScroll(rememberScrollState())
                                            .padding(10.dp)
                                    ) {
                                        Text(
                                            text = fileRec.reconstructedSourceCode.ifBlank { fileRec.rawPreview },
                                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            1 -> {
                session.patches.forEach { patch ->
                    val expanded = expandedItemId == patch.id
                    Card(
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        border = BorderStroke(1.dp, EmeraldVerified.copy(alpha = 0.45f))
                    ) {
                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                Text(patch.fileName, style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace), color = CyanBiometric, modifier = Modifier.weight(1f))
                                StatusPillBadge(label = patch.kind, color = EmeraldVerified)
                            }
                            Text(patch.title, style = MaterialTheme.typography.titleSmall)
                            Text("Cible : ${patch.targetPathHint}", style = MaterialTheme.typography.labelSmall, color = AmberWarning)
                            Text(patch.description, style = MaterialTheme.typography.bodySmall)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                TextButton(
                                    onClick = { expandedItemId = if (expanded) null else patch.id },
                                    modifier = Modifier.minimumInteractiveComponentSize()
                                ) {
                                    Text(if (expanded) "Masquer" else "Afficher patch")
                                }
                                OutlinedButton(
                                    onClick = {
                                        clipboard.setText(AnnotatedString(patch.codeContent))
                                        copiedId = patch.id
                                    },
                                    modifier = Modifier.minimumInteractiveComponentSize()
                                ) {
                                    Icon(if (copiedId == patch.id) Icons.Rounded.Check else Icons.Rounded.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text(if (copiedId == patch.id) "Copié" else "Copier")
                                }
                            }
                            AnimatedVisibility(visible = expanded) {
                                Surface(shape = MaterialTheme.shapes.small, color = MaterialTheme.colorScheme.background) {
                                    Box(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(10.dp)) {
                                        Text(patch.codeContent, style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace))
                                    }
                                }
                            }
                        }
                    }
                }
            }

            else -> {
                session.rawFilesManifest.keys.sorted().take(120).forEach { rel ->
                    val open = rawFilePreviewPath == rel
                    Card(
                        shape = MaterialTheme.shapes.small,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                    ) {
                        Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                Text(rel, style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace), color = CyanBiometric, modifier = Modifier.weight(1f))
                                TextButton(onClick = { rawFilePreviewPath = if (open) null else rel }) {
                                    Icon(Icons.Rounded.Description, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text(if (open) "Fermer" else "Lire")
                                }
                            }
                            AnimatedVisibility(visible = open) {
                                val text = remember(session.metadata.id, rel) { onReadSubFile(session, rel) }
                                Surface(shape = MaterialTheme.shapes.small, color = MaterialTheme.colorScheme.background) {
                                    Box(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(10.dp)) {
                                        Text(text, style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LiveCompareSection(
    sessions: List<LiveFodSession>,
    selectedAId: String?,
    selectedBId: String?,
    report: LiveComparisonReport?,
    isBusyZip: Boolean,
    onSelectPair: (String?, String?) -> Unit,
    onRunCompare: () -> Unit,
    onExportCompareZip: () -> Unit,
    onShareCompareZip: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            shape = MaterialTheme.shapes.medium,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Comparateur Live FOD (Exécution A vs B)", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Compare deux vraies tentatives d'enregistrement d'empreinte pour voir ce qui s'exécute sur votre ROM A et reste silencieux ou en erreur sur le GSI B.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                LiveSessionDropdown("Session Live A (ROM fonctionnelle)", sessions, selectedAId) {
                    onSelectPair(it, selectedBId)
                }
                LiveSessionDropdown("Session Live B (GSI / Cible)", sessions, selectedBId) {
                    onSelectPair(selectedAId, it)
                }

                Button(
                    onClick = onRunCompare,
                    enabled = sessions.size >= 2 && selectedAId != null && selectedBId != null && selectedAId != selectedBId,
                    modifier = Modifier
                        .fillMaxWidth()
                        .minimumInteractiveComponentSize()
                        .testTag("live_fod_run_compare_button"),
                    colors = ButtonDefaults.buttonColors(containerColor = CyanBiometric, contentColor = Color(0xFF051018))
                ) {
                    Icon(Icons.Rounded.CompareArrows, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("COMPARER LES TRACES LIVE")
                }
            }
        }

        if (report != null) {
            Card(
                shape = MaterialTheme.shapes.medium,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                border = BorderStroke(1.dp, if (report.blockersCount > 0) CrimsonCritical else EmeraldVerified)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Verdict comparatif d'exécution", style = MaterialTheme.typography.titleSmall)
                    Text(report.causalSummaryFr, style = MaterialTheme.typography.bodySmall)
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = onExportCompareZip,
                            enabled = !isBusyZip,
                            modifier = Modifier.weight(1f).minimumInteractiveComponentSize().testTag("live_compare_export_zip_button"),
                            colors = ButtonDefaults.buttonColors(containerColor = CyanBiometric, contentColor = Color(0xFF051018))
                        ) {
                            Icon(Icons.Rounded.Archive, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("EXPORTER COMPARE .ZIP", maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        OutlinedButton(
                            onClick = onShareCompareZip,
                            enabled = !isBusyZip,
                            modifier = Modifier.minimumInteractiveComponentSize()
                        ) {
                            Icon(Icons.Rounded.Share, contentDescription = "Partager", modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Partager")
                        }
                    }
                    report.exportedZipPath?.let { p ->
                        Text("Archive générée : $p", style = MaterialTheme.typography.labelSmall, color = EmeraldVerified)
                    }
                }
            }

            report.items.forEach { item ->
                val accent = if (item.isCriticalBlocker) CrimsonCritical else AmberWarning
                Card(
                    shape = MaterialTheme.shapes.medium,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, accent.copy(alpha = 0.45f))
                ) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                            Text(item.subject, style = MaterialTheme.typography.labelMedium, color = CyanBiometric, modifier = Modifier.weight(1f))
                            StatusPillBadge(label = if (item.isCriticalBlocker) "BLOQUANT" else "ÉCART", color = accent)
                        }
                        Text("A : ${item.valueInA}", style = MaterialTheme.typography.labelSmall, color = EmeraldVerified)
                        Text("B : ${item.valueInB}", style = MaterialTheme.typography.labelSmall, color = AmberWarning)
                        Text(item.factualExplanation, style = MaterialTheme.typography.bodySmall)
                        Text("Imitation : ${item.imitationAction}", style = MaterialTheme.typography.bodySmall, color = EmeraldVerified)
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LiveSessionDropdown(
    label: String,
    sessions: List<LiveFodSession>,
    selectedId: String?,
    onSelect: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val current = sessions.find { it.metadata.id == selectedId }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = !expanded }) {
        OutlinedTextField(
            value = current?.metadata?.displayName ?: "Sélectionner une session Live...",
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable)
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            sessions.forEach { s ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(s.metadata.displayName, style = MaterialTheme.typography.bodyMedium)
                            Text("${s.metadata.romType.labelFr} • ${s.metadata.extractedFilesCount} fichiers", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    },
                    onClick = {
                        onSelect(s.metadata.id)
                        expanded = false
                    }
                )
            }
        }
    }
}

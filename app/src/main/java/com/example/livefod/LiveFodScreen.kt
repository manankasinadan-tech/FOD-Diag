package com.example.livefod

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Archive
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.FiberManualRecord
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.TouchApp
import androidx.compose.material.icons.rounded.UploadFile
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.example.ui.components.StatusPillBadge
import com.example.ui.theme.AmberWarning
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyanBiometric
import com.example.ui.theme.EmeraldVerified

@Composable
fun LiveFodScreen(
    uiState: LiveFodUiState,
    rootGranted: Boolean,
    onStartCapture: (String) -> Unit,
    onMarkTouch: () -> Unit,
    onStopCapture: () -> Unit,
    onOpenEnrollSettings: () -> Unit,
    onSelectSession: (LiveFodSession) -> Unit,
    onDeleteSession: (LiveFodSession) -> Unit,
    onReadSubFile: (LiveFodSession, String) -> String,
    onImportZipUri: (android.net.Uri) -> Unit,
    onExportSessionZip: () -> Unit,
    onShareSessionZip: () -> Unit,
    onSelectComparePair: (String?, String?) -> Unit,
    onRunCompare: () -> Unit,
    onExportCompareZip: () -> Unit,
    onShareCompareZip: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var sessionLabelInput by rememberSaveable { mutableStateOf("") }
    var selectedSubTab by rememberSaveable { mutableIntStateOf(0) }

    val zipImportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) onImportZipUri(uri)
    }

    val notifPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { _ ->
        onStartCapture(sessionLabelInput)
    }

    val hud = uiState.hud
    val isActivePhase = hud.phase == LiveCapturePhase.CAPTURING_PRE ||
        hud.phase == LiveCapturePhase.RECORDING_LIVE ||
        hud.phase == LiveCapturePhase.CAPTURING_POST_AND_EXTRACTING

    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            modifier = Modifier
                .widthIn(max = 840.dp)
                .fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // ── PANNEAU DE CONTRÔLE LIVE FOD ─────────────────────────────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(
                        1.dp,
                        if (hud.phase == LiveCapturePhase.RECORDING_LIVE) CrimsonCritical else CyanBiometric.copy(alpha = 0.5f)
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Icon(Icons.Rounded.Fingerprint, contentDescription = null, tint = CyanBiometric)
                                Text("Live FOD — Interception d'enrôlement", style = MaterialTheme.typography.titleMedium)
                            }
                            StatusPillBadge(
                                label = if (rootGranted) "Root OK" else "Mode limité",
                                color = if (rootGranted) EmeraldVerified else AmberWarning
                            )
                        }

                        Text(
                            text = "Enregistre en direct chaque interaction (Logcat complet/filtré, dmesg, tactile getevent, transitions sysfs universelles, SurfaceFlinger, IPC /proc & strace) pendant que vous enregistrez une empreinte dans les Paramètres Android. Extrait tous les fichiers appelés dans la chaîne + leur code source + les patchs dans ${uiState.liveSessionsDirPath}.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        if (!isActivePhase) {
                            OutlinedTextField(
                                value = sessionLabelInput,
                                onValueChange = { sessionLabelInput = it },
                                label = { Text("Nom de session (ex. ROM_Origine_OK ou GSI_Echec)") },
                                singleLine = true,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("live_fod_label_input")
                            )

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Button(
                                    onClick = {
                                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                                            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                                        ) {
                                            notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                                        } else {
                                            onStartCapture(sessionLabelInput)
                                        }
                                    },
                                    modifier = Modifier
                                        .weight(1f)
                                        .minimumInteractiveComponentSize()
                                        .testTag("live_fod_start_button"),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = CyanBiometric,
                                        contentColor = Color(0xFF051018)
                                    )
                                ) {
                                    Icon(Icons.Rounded.FiberManualRecord, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(8.dp))
                                    Text("DÉMARRER LIVE FOD", maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }

                                OutlinedButton(
                                    onClick = onOpenEnrollSettings,
                                    modifier = Modifier
                                        .minimumInteractiveComponentSize()
                                        .testTag("live_fod_open_settings_button")
                                ) {
                                    Icon(Icons.Rounded.Settings, contentDescription = "Paramètres empreinte", modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(6.dp))
                                    Text("Paramètres")
                                }
                            }
                        } else {
                            // HUD CAPTURE ACTIVE
                            Surface(
                                shape = MaterialTheme.shapes.medium,
                                color = MaterialTheme.colorScheme.background,
                                border = BorderStroke(1.dp, CrimsonCritical.copy(alpha = 0.6f))
                            ) {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(10.dp)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = hud.phase.labelFr,
                                            style = MaterialTheme.typography.titleSmall,
                                            color = CrimsonCritical,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Text(
                                            text = "${hud.elapsedSeconds}s",
                                            style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace),
                                            color = CyanBiometric,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }

                                    if (hud.phase != LiveCapturePhase.RECORDING_LIVE) {
                                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                    }

                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .horizontalScroll(rememberScrollState()),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        StatusPillBadge("Logcat: ${hud.filteredFodEvents}/${hud.logcatRawLines}", CyanBiometric)
                                        StatusPillBadge("Noyau: ${hud.dmesgEvents}", AmberWarning)
                                        StatusPillBadge("Tactile: ${hud.touchEvents}", EmeraldVerified)
                                        StatusPillBadge("Sysfs Δ: ${hud.sysfsTransitions}", CyanBiometric)
                                        StatusPillBadge("HAL /proc: ${hud.halProcSnapshots}", EmeraldVerified)
                                    }

                                    if (hud.lastLiveHeadline.isNotBlank()) {
                                        Text(
                                            text = hud.lastLiveHeadline,
                                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                            color = MaterialTheme.colorScheme.onSurface
                                        )
                                    }

                                    if (hud.phase == LiveCapturePhase.RECORDING_LIVE) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            OutlinedButton(
                                                onClick = onOpenEnrollSettings,
                                                modifier = Modifier
                                                    .weight(1f)
                                                    .minimumInteractiveComponentSize()
                                                    .testTag("live_fod_hud_settings_button")
                                            ) {
                                                Icon(Icons.Rounded.Settings, contentDescription = null, modifier = Modifier.size(18.dp))
                                                Spacer(Modifier.width(6.dp))
                                                Text("Paramètres Empreinte", maxLines = 1, overflow = TextOverflow.Ellipsis)
                                            }
                                            OutlinedButton(
                                                onClick = onMarkTouch,
                                                modifier = Modifier
                                                    .minimumInteractiveComponentSize()
                                                    .testTag("live_fod_mark_touch_button")
                                            ) {
                                                Icon(Icons.Rounded.TouchApp, contentDescription = "Marquer toucher", modifier = Modifier.size(18.dp))
                                                Spacer(Modifier.width(4.dp))
                                                Text("Marquer (${hud.touchMarkersCount})")
                                            }
                                        }

                                        Button(
                                            onClick = onStopCapture,
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .minimumInteractiveComponentSize()
                                                .testTag("live_fod_stop_button"),
                                            colors = ButtonDefaults.buttonColors(containerColor = CrimsonCritical, contentColor = Color.White)
                                        ) {
                                            Icon(Icons.Rounded.Stop, contentDescription = null, modifier = Modifier.size(18.dp))
                                            Spacer(Modifier.width(8.dp))
                                            Text("ARRÊTER & COMPILER LA SESSION LIVE")
                                        }
                                    }
                                }
                            }
                        }

                        hud.errorMessage?.let { err ->
                            Text("Erreur : $err", style = MaterialTheme.typography.bodySmall, color = CrimsonCritical)
                        }
                    }
                }
            }

            // ── IMPORT .ZIP / EXPORT .ZIP & SESSIONS SAUVEGARDÉES ───────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.medium,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text("Archives & Sessions Live FOD (${uiState.sessions.size})", style = MaterialTheme.typography.titleSmall)

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = { zipImportLauncher.launch(arrayOf("application/zip", "application/octet-stream", "*/*")) },
                                enabled = !uiState.isBusyZip,
                                modifier = Modifier
                                    .weight(1f)
                                    .minimumInteractiveComponentSize()
                                    .testTag("live_fod_import_zip_button")
                            ) {
                                Icon(Icons.Rounded.UploadFile, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("IMPORTER .ZIP", maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }

                            Button(
                                onClick = onExportSessionZip,
                                enabled = uiState.activeSession != null && !uiState.isBusyZip,
                                modifier = Modifier
                                    .weight(1f)
                                    .minimumInteractiveComponentSize()
                                    .testTag("live_fod_export_zip_button"),
                                colors = ButtonDefaults.buttonColors(containerColor = CyanBiometric, contentColor = Color(0xFF051018))
                            ) {
                                Icon(Icons.Rounded.Archive, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("EXPORTER .ZIP", maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }

                            IconButton(
                                onClick = onShareSessionZip,
                                enabled = uiState.activeSession != null && !uiState.isBusyZip,
                                modifier = Modifier
                                    .minimumInteractiveComponentSize()
                                    .testTag("live_fod_share_zip_button")
                            ) {
                                Icon(Icons.Rounded.Share, contentDescription = "Partager le .zip Live FOD")
                            }
                        }

                        if (uiState.sessions.isNotEmpty()) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .horizontalScroll(rememberScrollState()),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                uiState.sessions.forEach { session ->
                                    val selected = uiState.activeSession?.metadata?.id == session.metadata.id
                                    FilterChip(
                                        selected = selected,
                                        onClick = { onSelectSession(session) },
                                        label = {
                                            Text(
                                                "${session.metadata.displayName} (${session.metadata.extractedFilesCount}f)",
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        },
                                        trailingIcon = {
                                            IconButton(
                                                onClick = { onDeleteSession(session) },
                                                modifier = Modifier.size(20.dp)
                                            ) {
                                                Icon(
                                                    Icons.Rounded.DeleteOutline,
                                                    contentDescription = "Supprimer ${session.metadata.displayName}",
                                                    modifier = Modifier.size(16.dp)
                                                )
                                            }
                                        }
                                    )
                                }
                            }
                        } else {
                            Text(
                                text = "Aucune session Live enregistrée. Lancez une capture puis allez dans Paramètres > Empreintes, ou importez un .zip Live FOD.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            // ── SOUS-ONGLETS D'EXPLORATION & COMPARAISON LIVE ────────────────────────
            if (uiState.activeSession != null || uiState.sessions.size >= 2) {
                item {
                    val tabs = listOf("Mécanisme", "Chronologie", "Fichiers & Sources", "Comparer Live")
                    ScrollableTabRow(
                        selectedTabIndex = selectedSubTab,
                        containerColor = MaterialTheme.colorScheme.surface,
                        edgePadding = 8.dp
                    ) {
                        tabs.forEachIndexed { idx, title ->
                            Tab(
                                selected = selectedSubTab == idx,
                                onClick = { selectedSubTab = idx },
                                text = { Text(title) },
                                modifier = Modifier.testTag("live_fod_tab_$idx")
                            )
                        }
                    }
                }

                item {
                    when (selectedSubTab) {
                        0 -> uiState.activeSession?.let { LiveMechanismSection(it) }
                        1 -> uiState.activeSession?.let { LiveTimelineSection(it) }
                        2 -> uiState.activeSession?.let {
                            LiveFilesSourcesPatchesSection(session = it, onReadSubFile = onReadSubFile)
                        }
                        3 -> LiveCompareSection(
                            sessions = uiState.sessions,
                            selectedAId = uiState.selectedCompareAId,
                            selectedBId = uiState.selectedCompareBId,
                            report = uiState.comparisonReport,
                            isBusyZip = uiState.isBusyZip,
                            onSelectPair = onSelectComparePair,
                            onRunCompare = onRunCompare,
                            onExportCompareZip = onExportCompareZip,
                            onShareCompareZip = onShareCompareZip
                        )
                    }
                }
            }
        }
    }
}

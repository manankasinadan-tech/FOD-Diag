package com.example.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Storage
import androidx.compose.material.icons.rounded.UploadFile
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.model.FodSnapshot
import com.example.ui.components.SnapshotCard
import com.example.ui.components.StatusPillBadge
import com.example.ui.theme.AmberWarning
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyanBiometric
import com.example.ui.theme.EmeraldVerified
import com.example.ui.viewmodel.FodLabUiState

@Composable
fun HomeScreen(
    state: FodLabUiState,
    onLaunchAnalysis: () -> Unit,
    onImportZipUri: (android.net.Uri) -> Unit,
    onRefreshEnvironment: () -> Unit,
    onOpenSnapshotDashboard: (FodSnapshot) -> Unit,
    onDeleteSnapshot: (FodSnapshot) -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier
) {
    val zipPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            onImportZipUri(uri)
        }
    }

    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            modifier = Modifier
                .widthIn(max = 760.dp)
                .fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // ── HERO BANNER ─────────────────────────────────────────────────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Box(modifier = Modifier.fillMaxWidth()) {
                        Image(
                            painter = painterResource(id = R.drawable.img_fod_lab_hero),
                            contentDescription = stringResource(id = R.string.hero_banner_desc),
                            contentScale = ContentScale.Crop,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(168.dp)
                        )
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(168.dp)
                                .background(
                                    Brush.verticalGradient(
                                        colors = listOf(
                                            Color(0x66070B12),
                                            Color(0xEE0E1522)
                                        )
                                    )
                                )
                        )
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp)
                                .align(Alignment.BottomStart),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                StatusPillBadge(
                                    label = "Moteur 100 % Factuel",
                                    color = CyanBiometric
                                )
                                IconButton(
                                    onClick = onRefreshEnvironment,
                                    modifier = Modifier
                                        .minimumInteractiveComponentSize()
                                        .testTag("refresh_env_button")
                                ) {
                                    Icon(
                                        imageVector = Icons.Rounded.Refresh,
                                        contentDescription = "Actualiser l'état système",
                                        tint = Color.White
                                    )
                                }
                            }
                            Text(
                                text = "FOD LAB INTELLIGENCE",
                                style = MaterialTheme.typography.headlineMedium,
                                color = Color.White
                            )
                            Text(
                                text = "Investigation à froid & en direct du lecteur d'empreintes sous écran (ROM d'origine vs GSI).",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFFD6E3F3)
                            )
                        }
                    }

                    // État d'environnement système
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            StatusPillBadge(
                                label = if (state.envStatus.rootGranted) {
                                    "Root : ${state.envStatus.rootProvider}"
                                } else {
                                    "Root : Non activé"
                                },
                                color = if (state.envStatus.rootGranted) EmeraldVerified else CrimsonCritical
                            )
                            StatusPillBadge(
                                label = if (state.envStatus.storageGranted && state.envStatus.databaseWritable) {
                                    "Stockage OK"
                                } else {
                                    "Stockage limité"
                                },
                                color = if (state.envStatus.storageGranted && state.envStatus.databaseWritable) EmeraldVerified else AmberWarning
                            )
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            StatusPillBadge(
                                label = state.envStatus.detectedRomType.labelFr,
                                color = if (state.envStatus.isDsuDetected) AmberWarning else CyanBiometric
                            )
                            StatusPillBadge(
                                label = "SELinux : ${state.envStatus.seLinuxMode}",
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        if (!state.envStatus.rootGranted || !state.envStatus.storageGranted) {
                            OutlinedButton(
                                onClick = onOpenSettings,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .minimumInteractiveComponentSize()
                                    .testTag("home_open_permissions_button"),
                                shape = MaterialTheme.shapes.medium
                            ) {
                                Icon(Icons.Rounded.Shield, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text("Activer Root (SU) & Stockage dans Paramètres")
                            }
                        }
                    }
                }
            }

            // ── BOUTON PRINCIPAL : LANCER L'ANALYSE FOD ─────────────────────────────────
            item {
                Button(
                    onClick = onLaunchAnalysis,
                    enabled = !state.progress.isRunning,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(64.dp)
                        .testTag("launch_fod_analysis_button"),
                    shape = MaterialTheme.shapes.large,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CyanBiometric,
                        contentColor = Color(0xFF051018)
                    )
                ) {
                    if (state.progress.isRunning) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(22.dp),
                            strokeWidth = 2.5.dp,
                            color = Color(0xFF051018)
                        )
                        Spacer(Modifier.width(12.dp))
                        Text(
                            text = "INVESTIGATION EN COURS (${state.progress.currentPhaseIndex}/${state.progress.totalPhases})...",
                            style = MaterialTheme.typography.labelLarge
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Rounded.Fingerprint,
                            contentDescription = null,
                            modifier = Modifier.size(26.dp)
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(
                            text = stringResource(id = R.string.cta_launch_analysis),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.width(8.dp))
                        Icon(imageVector = Icons.Rounded.PlayArrow, contentDescription = null)
                    }
                }
            }

            // ── CONSOLE DE PROGRESSION TEMPS RÉEL ───────────────────────────────────────
            item {
                AnimatedVisibility(visible = state.progress.isRunning || state.progress.liveLogs.isNotEmpty()) {
                    Card(
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        border = BorderStroke(1.dp, CyanBiometric.copy(alpha = 0.45f))
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
                                Text(
                                    text = state.progress.currentPhaseTitle.ifBlank { "Journal d'exécution" },
                                    style = MaterialTheme.typography.titleSmall,
                                    color = CyanBiometric
                                )
                                Text(
                                    text = "${(state.progress.progressFraction * 100).toInt()}%",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = EmeraldVerified
                                )
                            }
                            LinearProgressIndicator(
                                progress = { state.progress.progressFraction },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(6.dp)
                                    .clip(RoundedCornerShape(3.dp)),
                                color = CyanBiometric,
                                trackColor = MaterialTheme.colorScheme.surfaceVariant
                            )
                            Surface(
                                shape = MaterialTheme.shapes.small,
                                color = MaterialTheme.colorScheme.background
                            ) {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(10.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    state.progress.liveLogs.takeLast(6).forEach { line ->
                                        Text(
                                            text = line,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurface
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── MODULE IMPORTATEUR (.ZIP) SUR L'ACCUEIL ─────────────────────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.medium,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, AmberWarning.copy(alpha = 0.45f))
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.UploadFile,
                                contentDescription = "Importateur ZIP",
                                tint = AmberWarning,
                                modifier = Modifier.size(24.dp)
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "IMPORTATEUR D'ARCHIVES .ZIP",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = "Décompresse automatiquement vos captures (.zip ROM d'origine ou GSI) dans /sdcard/FOD Database/ pour comparaison.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                        OutlinedButton(
                            onClick = {
                                zipPickerLauncher.launch(arrayOf("application/zip", "application/x-zip-compressed", "*/*"))
                            },
                            enabled = !state.isBusyImportingOrExporting,
                            modifier = Modifier
                                .fillMaxWidth()
                                .minimumInteractiveComponentSize()
                                .testTag("importer_zip_button"),
                            shape = MaterialTheme.shapes.medium
                        ) {
                            if (state.isBusyImportingOrExporting) {
                                CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                                Spacer(Modifier.width(8.dp))
                                Text("Décompression en cours...")
                            } else {
                                Icon(Icons.Rounded.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(id = R.string.cta_importer_zip))
                            }
                        }
                    }
                }
            }

            // ── BASE DE CONNAISSANCES / CAPTURES ENREGISTRÉES ────────────────────────────
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Rounded.Storage, contentDescription = null, tint = CyanBiometric, modifier = Modifier.size(18.dp))
                        Text(
                            text = "Base de connaissances (${state.snapshots.size})",
                            style = MaterialTheme.typography.titleMedium
                        )
                    }
                    Text(
                        text = state.envStatus.databasePath,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            if (state.snapshots.isEmpty()) {
                item {
                    Card(
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Fingerprint,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(38.dp)
                            )
                            Text(
                                text = "Aucune capture FOD dans la base",
                                style = MaterialTheme.typography.titleSmall
                            )
                            Text(
                                text = "Appuyez sur LANCER L’ANALYSE FOD pour inspecter ce système ou utilisez l'IMPORTATEUR pour charger une archive .zip.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            } else {
                items(state.snapshots, key = { it.metadata.id }) { snapshot ->
                    SnapshotCard(
                        snapshot = snapshot,
                        isActive = state.activeSnapshot?.metadata?.id == snapshot.metadata.id,
                        onOpenDashboard = { onOpenSnapshotDashboard(snapshot) },
                        onDelete = { onDeleteSnapshot(snapshot) }
                    )
                }
            }
        }
    }
}

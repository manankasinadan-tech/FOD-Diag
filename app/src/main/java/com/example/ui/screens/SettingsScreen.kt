package com.example.ui.screens

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.core.PermissionHelper
import com.example.ui.components.StatusPillBadge
import com.example.ui.theme.AmberWarning
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyanBiometric
import com.example.ui.theme.EmeraldVerified
import com.example.ui.viewmodel.FodLabUiState

@Composable
fun SettingsScreen(
    state: FodLabUiState,
    onRefreshEnvironment: () -> Unit,
    onTestRootPermission: () -> Unit,
    onToggleDeepBinary: (Boolean) -> Unit,
    onToggleAutoDashboard: (Boolean) -> Unit,
    onToggleDarkTheme: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    val allFilesSettingsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        onRefreshEnvironment()
    }

    val legacyStorageLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) {
        onRefreshEnvironment()
    }

    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            modifier = Modifier
                .widthIn(max = 760.dp)
                .fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // ── AUTORISATION DE STOCKAGE (/sdcard/FOD Database/) ────────────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(
                        1.dp,
                        if (state.envStatus.storageGranted) EmeraldVerified.copy(alpha = 0.5f) else AmberWarning.copy(alpha = 0.55f)
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Icon(Icons.Rounded.Folder, contentDescription = null, tint = CyanBiometric)
                                Text("Autorisation de stockage", style = MaterialTheme.typography.titleMedium)
                            }
                            StatusPillBadge(
                                label = if (state.envStatus.storageGranted) "Activée" else "Requise",
                                color = if (state.envStatus.storageGranted) EmeraldVerified else AmberWarning
                            )
                        }
                        Text(
                            text = "Permet de créer et gérer librement « /sdcard/FOD Database/ » ainsi que les archives .zip exportées et importées.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "Dossier actif : ${state.envStatus.databasePath} (${if (state.envStatus.databaseWritable) "écriture vérifiée" else "accès restreint"})",
                            style = MaterialTheme.typography.labelSmall,
                            color = CyanBiometric
                        )
                        Button(
                            onClick = {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                    allFilesSettingsLauncher.launch(PermissionHelper.buildManageAllFilesIntent(context))
                                } else {
                                    legacyStorageLauncher.launch(
                                        arrayOf(
                                            Manifest.permission.READ_EXTERNAL_STORAGE,
                                            Manifest.permission.WRITE_EXTERNAL_STORAGE
                                        )
                                    )
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .minimumInteractiveComponentSize()
                                .testTag("request_storage_permission_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = CyanBiometric,
                                contentColor = Color(0xFF051018)
                            )
                        ) {
                            Text(
                                if (state.envStatus.storageGranted) {
                                    "Vérifier / Gérer l'autorisation de stockage"
                                } else {
                                    "ACTIVER L’AUTORISATION DE STOCKAGE"
                                }
                            )
                        }
                    }
                }
            }

            // ── AUTORISATION ROOT (MAGISK / SU) ─────────────────────────────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(
                        1.dp,
                        if (state.envStatus.rootGranted) EmeraldVerified.copy(alpha = 0.5f) else CrimsonCritical.copy(alpha = 0.55f)
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Icon(Icons.Rounded.AdminPanelSettings, contentDescription = null, tint = CyanBiometric)
                                Text("Autorisation Root (Magisk / SU)", style = MaterialTheme.typography.titleMedium)
                            }
                            StatusPillBadge(
                                label = if (state.envStatus.rootGranted) state.envStatus.rootProvider else "Refusée / Inactive",
                                color = if (state.envStatus.rootGranted) EmeraldVerified else CrimsonCritical
                            )
                        }
                        Text(
                            text = "Indispensable pour explorer en lecture seule /vendor, /proc/device-tree, dmesg, lshal, sysfs protégés et les contextes SELinux.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = state.envStatus.rootDetail,
                            style = MaterialTheme.typography.labelSmall,
                            color = if (state.envStatus.rootGranted) EmeraldVerified else AmberWarning
                        )
                        Button(
                            onClick = onTestRootPermission,
                            modifier = Modifier
                                .fillMaxWidth()
                                .minimumInteractiveComponentSize()
                                .testTag("request_root_permission_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (state.envStatus.rootGranted) EmeraldVerified else CyanBiometric,
                                contentColor = Color(0xFF051018)
                            )
                        ) {
                            Text(
                                if (state.envStatus.rootGranted) {
                                    "RE-TESTER L’ACCÈS ROOT (MAGISK / SU)"
                                } else {
                                    "ACTIVER / DEMANDER L’AUTORISATION ROOT"
                                }
                            )
                        }
                    }
                }
            }

            // ── OPTIONS DU MOTEUR D'INVESTIGATION ───────────────────────────────────────
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
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Icon(Icons.Rounded.Tune, contentDescription = null, tint = CyanBiometric)
                            Text("Paramètres d'analyse", style = MaterialTheme.typography.titleMedium)
                        }

                        SettingToggleRow(
                            title = "Inspection binaire complète (ELF, DEX, RRO)",
                            subtitle = "Analyse approfondie des symboles .so, DT_NEEDED et classes UDFPS sans modifier aucun APK.",
                            checked = state.settings.deepBinaryInspection,
                            onCheckedChange = onToggleDeepBinary,
                            testTag = "toggle_deep_binary"
                        )

                        SettingToggleRow(
                            title = "Ouvrir le tableau de bord après analyse",
                            subtitle = "Affiche automatiquement le bilan et le bouton d'export .zip dès la fin du scan.",
                            checked = state.settings.autoOpenDashboardAfterScan,
                            onCheckedChange = onToggleAutoDashboard,
                            testTag = "toggle_auto_dashboard"
                        )

                        SettingToggleRow(
                            title = "Thème sombre laboratoire",
                            subtitle = "Palette sombre haute lisibilité pour l'inspection technique.",
                            checked = state.settings.darkTheme,
                            onCheckedChange = onToggleDarkTheme,
                            testTag = "toggle_dark_theme"
                        )
                    }
                }
            }

            // ── GARDE-FOU BIOMÉTRIQUE ───────────────────────────────────────────────────
            item {
                Card(
                    shape = MaterialTheme.shapes.medium,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, EmeraldVerified.copy(alpha = 0.4f))
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(Icons.Rounded.Lock, contentDescription = null, tint = EmeraldVerified, modifier = Modifier.size(22.dp))
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Respect des données biométriques", style = MaterialTheme.typography.titleSmall)
                            Text(
                                "Le moteur fonctionne en lecture seule sur la configuration système et bloque systématiquement la lecture ou l'exportation des gabarits biométriques (/fpdata/), du stockage TEE et des clés matérielles.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    testTag: String
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            modifier = Modifier.testTag(testTag)
        )
    }
}

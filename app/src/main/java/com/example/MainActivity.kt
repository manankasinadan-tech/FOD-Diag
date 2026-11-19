package com.example

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountTree
import androidx.compose.material.icons.outlined.CompareArrows
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.rounded.AccountTree
import androidx.compose.material.icons.rounded.CompareArrows
import androidx.compose.material.icons.rounded.Dashboard
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.ui.screens.ComparatorScreen
import com.example.ui.screens.DashboardScreen
import com.example.ui.screens.HomeScreen
import com.example.ui.screens.MappingScreen
import com.example.ui.screens.SettingsScreen
import com.example.ui.theme.FodLabTheme
import com.example.ui.viewmodel.FodLabViewModel
import com.example.ui.viewmodel.LabUiEvent

private enum class LabRoute(
    val route: String,
    val labelFr: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val testTag: String
) {
    ACCUEIL("accueil", "Accueil", Icons.Rounded.Home, Icons.Outlined.Home, "nav_accueil"),
    TABLEAU_DE_BORD("tableau_de_bord", "Tableau", Icons.Rounded.Dashboard, Icons.Outlined.Dashboard, "nav_tableau"),
    CARTOGRAPHIE("cartographie", "Carte FOD", Icons.Rounded.AccountTree, Icons.Outlined.AccountTree, "nav_cartographie"),
    COMPARATEUR("comparateur", "Comparer", Icons.Rounded.CompareArrows, Icons.Outlined.CompareArrows, "nav_comparateur"),
    PARAMETRES("parametres", "Paramètres", Icons.Rounded.Settings, Icons.Outlined.Settings, "nav_parametres")
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val viewModel: FodLabViewModel = viewModel()
            val uiState by viewModel.uiState.collectAsStateWithLifecycle()

            FodLabTheme(darkTheme = uiState.settings.darkTheme) {
                FodLabApp(viewModel = viewModel)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FodLabApp(viewModel: FodLabViewModel) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val navController = rememberNavController()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route ?: LabRoute.ACCUEIL.route

    fun navigateTo(route: String) {
        navController.navigate(route) {
            popUpTo(navController.graph.findStartDestination().id) {
                saveState = true
            }
            launchSingleTop = true
            restoreState = true
        }
    }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                LabUiEvent.NavigateToDashboard -> navigateTo(LabRoute.TABLEAU_DE_BORD.route)
                is LabUiEvent.ShareZipFile -> {
                    runCatching {
                        val uri = FileProvider.getUriForFile(
                            context,
                            "${context.packageName}.fileprovider",
                            event.file
                        )
                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "application/zip"
                            putExtra(Intent.EXTRA_STREAM, uri)
                            putExtra(Intent.EXTRA_SUBJECT, "Capture FOD Lab : ${event.file.name}")
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        context.startActivity(Intent.createChooser(shareIntent, "Partager l'archive FOD .zip"))
                    }
                }
            }
        }
    }

    LaunchedEffect(uiState.statusBannerMessage, uiState.errorBannerMessage) {
        val msg = uiState.errorBannerMessage ?: uiState.statusBannerMessage
        if (!msg.isNullOrBlank()) {
            snackbarHostState.showSnackbar(msg)
            viewModel.clearBanners()
        }
    }

    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val useNavRail = maxWidth >= 680.dp

        Scaffold(
            contentWindowInsets = WindowInsets.safeDrawing,
            topBar = {
                val activeTitle = when (currentRoute) {
                    LabRoute.ACCUEIL.route -> "FOD Lab Intelligence"
                    LabRoute.TABLEAU_DE_BORD.route -> "Tableau de bord FOD"
                    LabRoute.CARTOGRAPHIE.route -> "Cartographie & Artefacts"
                    LabRoute.COMPARATEUR.route -> "Comparateur Stock vs GSI"
                    LabRoute.PARAMETRES.route -> "Paramètres & Autorisations"
                    else -> "FOD Lab Intelligence"
                }
                TopAppBar(
                    title = {
                        Text(
                            text = activeTitle,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface,
                        titleContentColor = MaterialTheme.colorScheme.onSurface
                    )
                )
            },
            bottomBar = {
                if (!useNavRail) {
                    NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                        LabRoute.entries.forEach { dest ->
                            val selected = currentRoute == dest.route
                            NavigationBarItem(
                                selected = selected,
                                onClick = { navigateTo(dest.route) },
                                icon = {
                                    Icon(
                                        imageVector = if (selected) dest.selectedIcon else dest.unselectedIcon,
                                        contentDescription = dest.labelFr
                                    )
                                },
                                label = {
                                    Text(
                                        text = dest.labelFr,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                },
                                modifier = Modifier.testTag(dest.testTag)
                            )
                        }
                    }
                }
            },
            snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
        ) { innerPadding ->
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                if (useNavRail) {
                    NavigationRail(containerColor = MaterialTheme.colorScheme.surface) {
                        LabRoute.entries.forEach { dest ->
                            val selected = currentRoute == dest.route
                            NavigationRailItem(
                                selected = selected,
                                onClick = { navigateTo(dest.route) },
                                icon = {
                                    Icon(
                                        imageVector = if (selected) dest.selectedIcon else dest.unselectedIcon,
                                        contentDescription = dest.labelFr
                                    )
                                },
                                label = { Text(dest.labelFr) },
                                modifier = Modifier.testTag(dest.testTag)
                            )
                        }
                    }
                }

                NavHost(
                    navController = navController,
                    startDestination = LabRoute.ACCUEIL.route,
                    modifier = Modifier.weight(1f)
                ) {
                    composable(LabRoute.ACCUEIL.route) {
                        HomeScreen(
                            state = uiState,
                            onLaunchAnalysis = { viewModel.launchFodAnalysis() },
                            onImportZipUri = { uri -> viewModel.importZipArchive(uri) },
                            onRefreshEnvironment = { viewModel.refreshEnvironmentAndSnapshots() },
                            onOpenSnapshotDashboard = { snap ->
                                viewModel.selectActiveSnapshot(snap)
                                navigateTo(LabRoute.TABLEAU_DE_BORD.route)
                            },
                            onDeleteSnapshot = { snap -> viewModel.deleteSnapshot(snap) },
                            onOpenSettings = { navigateTo(LabRoute.PARAMETRES.route) }
                        )
                    }

                    composable(LabRoute.TABLEAU_DE_BORD.route) {
                        DashboardScreen(
                            snapshot = uiState.activeSnapshot,
                            isExporting = uiState.isBusyImportingOrExporting,
                            onExportZip = { viewModel.exportActiveSnapshotToZip(shareAfterExport = false) },
                            onShareZip = { viewModel.exportActiveSnapshotToZip(shareAfterExport = true) },
                            onGoToHome = { navigateTo(LabRoute.ACCUEIL.route) }
                        )
                    }

                    composable(LabRoute.CARTOGRAPHIE.route) {
                        MappingScreen(snapshot = uiState.activeSnapshot)
                    }

                    composable(LabRoute.COMPARATEUR.route) {
                        ComparatorScreen(
                            snapshots = uiState.snapshots,
                            selectedAId = uiState.selectedSnapshotAId,
                            selectedBId = uiState.selectedSnapshotBId,
                            report = uiState.comparisonReport,
                            onSelectSnapshots = { a, b -> viewModel.selectComparisonSnapshots(a, b) },
                            onRunComparison = { viewModel.runComparison() }
                        )
                    }

                    composable(LabRoute.PARAMETRES.route) {
                        SettingsScreen(
                            state = uiState,
                            onRefreshEnvironment = { viewModel.refreshEnvironmentAndSnapshots() },
                            onTestRootPermission = { viewModel.testRootPermissionExplicitly() },
                            onToggleDeepBinary = { viewModel.setDeepBinaryInspection(it) },
                            onToggleAutoDashboard = { viewModel.setAutoOpenDashboard(it) },
                            onToggleDarkTheme = { viewModel.setDarkTheme(it) }
                        )
                    }
                }
            }
        }
    }
}

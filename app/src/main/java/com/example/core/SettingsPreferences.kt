package com.example.core

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.fodDataStore by preferencesDataStore(name = "fod_lab_prefs")

data class LabSettings(
    val deepBinaryInspection: Boolean = true,
    val darkTheme: Boolean = true,
    val autoOpenDashboardAfterScan: Boolean = true
)

class SettingsPreferences(private val context: Context) {

    private object Keys {
        val DEEP_BINARY = booleanPreferencesKey("deep_binary_inspection")
        val DARK_THEME = booleanPreferencesKey("dark_theme")
        val AUTO_DASHBOARD = booleanPreferencesKey("auto_open_dashboard")
    }

    val settingsFlow: Flow<LabSettings> = context.fodDataStore.data.map { prefs ->
        LabSettings(
            deepBinaryInspection = prefs[Keys.DEEP_BINARY] ?: true,
            darkTheme = prefs[Keys.DARK_THEME] ?: true,
            autoOpenDashboardAfterScan = prefs[Keys.AUTO_DASHBOARD] ?: true
        )
    }

    suspend fun setDeepBinaryInspection(enabled: Boolean) {
        context.fodDataStore.edit { it[Keys.DEEP_BINARY] = enabled }
    }

    suspend fun setDarkTheme(enabled: Boolean) {
        context.fodDataStore.edit { it[Keys.DARK_THEME] = enabled }
    }

    suspend fun setAutoOpenDashboard(enabled: Boolean) {
        context.fodDataStore.edit { it[Keys.AUTO_DASHBOARD] = enabled }
    }
}

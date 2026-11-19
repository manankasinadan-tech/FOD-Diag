package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

private val FodDarkColorScheme = darkColorScheme(
    primary = CyanBiometric,
    onPrimary = ObsidianBg,
    primaryContainer = CyanContainer,
    onPrimaryContainer = CyanBiometric,
    secondary = EmeraldVerified,
    onSecondary = ObsidianBg,
    secondaryContainer = EmeraldContainer,
    onSecondaryContainer = EmeraldVerified,
    tertiary = AmberWarning,
    onTertiary = ObsidianBg,
    tertiaryContainer = AmberContainer,
    onTertiaryContainer = AmberWarning,
    error = CrimsonCritical,
    onError = ObsidianBg,
    errorContainer = CrimsonContainer,
    onErrorContainer = CrimsonCritical,
    background = ObsidianBg,
    onBackground = TextPrimaryDark,
    surface = ObsidianSurface,
    onSurface = TextPrimaryDark,
    surfaceVariant = ObsidianSurfaceVariant,
    onSurfaceVariant = TextSecondaryDark,
    surfaceContainerHigh = ObsidianSurfaceElevated,
    outline = ObsidianOutline,
    outlineVariant = ColorTokens.OutlineSubtle
)

private val FodLightColorScheme = lightColorScheme(
    primary = CyanPrimaryLight,
    onPrimary = LabLightSurface,
    primaryContainer = CyanContainerLight,
    onPrimaryContainer = CyanPrimaryLight,
    secondary = EmeraldLight,
    onSecondary = LabLightSurface,
    background = LabLightBg,
    onBackground = TextPrimaryLight,
    surface = LabLightSurface,
    onSurface = TextPrimaryLight,
    surfaceVariant = LabLightSurfaceVariant,
    onSurfaceVariant = TextSecondaryLight,
    outline = LabLightOutline
)

private object ColorTokens {
    val OutlineSubtle = androidx.compose.ui.graphics.Color(0xFF1D2C43)
}

val FodShapes = Shapes(
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(26.dp)
)

@Composable
fun FodLabTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) FodDarkColorScheme else FodLightColorScheme
    MaterialTheme(
        colorScheme = colorScheme,
        typography = FodTypography,
        shapes = FodShapes,
        content = content
    )
}

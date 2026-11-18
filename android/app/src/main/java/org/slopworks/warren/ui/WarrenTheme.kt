package org.slopworks.warren.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val LightColors = lightColorScheme(
    primary = Color(0xFF4A539C),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE2E3FF),
    onPrimaryContainer = Color(0xFF252850),
    secondary = Color(0xFF513D56),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE9DFED),
    onSecondaryContainer = Color(0xFF513D56),
    tertiary = Color(0xFF8E4D30),
    tertiaryContainer = Color(0xFFF3BC9B),
    onTertiaryContainer = Color(0xFF5A3526),
    surface = Color(0xFFFBF9FF),
    onSurface = Color(0xFF1B1C29),
    onSurfaceVariant = Color(0xFF505161),
    surfaceContainer = Color(0xFFF0EEF7),
    surfaceContainerHigh = Color(0xFFEAE8F3),
    outline = Color(0xFF6A6A7C),
    outlineVariant = Color(0xFFC6C5D5),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFB9C2FF),
    onPrimary = Color(0xFF202A68),
    primaryContainer = Color(0xFF33375E),
    onPrimaryContainer = Color(0xFFEDEAFF),
    secondary = Color(0xFFF2DCEF),
    onSecondary = Color(0xFF413449),
    secondaryContainer = Color(0xFF413449),
    onSecondaryContainer = Color(0xFFF2DCEF),
    tertiary = Color(0xFFE7B998),
    tertiaryContainer = Color(0xFF63432E),
    onTertiaryContainer = Color(0xFFFCD5B9),
    surface = Color(0xFF15151F),
    onSurface = Color(0xFFEEEEF7),
    onSurfaceVariant = Color(0xFFC5C4D4),
    surfaceContainer = Color(0xFF22222E),
    surfaceContainerHigh = Color(0xFF2D2C3B),
    outline = Color(0xFFA5A5BA),
    outlineVariant = Color(0xFF515163),
)

private val WarrenTypography = Typography(
    headlineLarge = TextStyle(
        fontSize = 38.sp,
        lineHeight = 42.sp,
        letterSpacing = (-1.2).sp,
        fontWeight = FontWeight.SemiBold,
    ),
    titleLarge = TextStyle(
        fontSize = 25.sp,
        lineHeight = 31.sp,
        letterSpacing = (-0.9).sp,
        fontWeight = FontWeight.Bold,
    ),
    labelLarge = TextStyle(
        fontSize = 16.sp,
        lineHeight = 20.sp,
        fontWeight = FontWeight.SemiBold,
    ),
)

@Composable
internal fun WarrenTheme(content: @Composable () -> Unit) {
    val isDark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        if (isDark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    } else {
        if (isDark) DarkColors else LightColors
    }
    MaterialExpressiveTheme(
        colorScheme = colors,
        motionScheme = MotionScheme.expressive(),
        typography = WarrenTypography,
        content = content,
    )
}

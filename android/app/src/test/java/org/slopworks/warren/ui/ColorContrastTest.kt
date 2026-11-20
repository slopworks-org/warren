package org.slopworks.warren.ui

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

internal val CyanDark = darkColorScheme(
    surface = Color(0xFF001228),
    surfaceContainer = Color(0xFF00243C),
    surfaceContainerHigh = Color(0xFF002E4A),
    onSurface = Color(0xFFE3F0FC),
    onSurfaceVariant = Color(0xFFA7BAC9),
    primary = Color(0xFF74CEFA),
    onPrimary = Color(0xFF003549),
    primaryContainer = Color(0xFF00C9FF),
    onPrimaryContainer = Color(0xFF002536),
    tertiary = Color(0xFFB6B3FE),
)

internal val CyanLight = lightColorScheme(
    surface = Color(0xFFF4F8FF),
    surfaceContainer = Color(0xFFDFEEFF),
    surfaceContainerHigh = Color(0xFFD4E6FA),
    onSurface = Color(0xFF082436),
    onSurfaceVariant = Color(0xFF435A6B),
    primary = Color(0xFF006589),
    onPrimary = Color.White,
    primaryContainer = Color(0xFF00C9FF),
    onPrimaryContainer = Color(0xFF002536),
    tertiaryContainer = Color(0xFFC1BCFC),
)

class ColorContrastTest {
    @Test
    fun darkTunnelDimsBrightActiveAndRecoveringBackdrops() {
        val brightContainers = CyanDark.copy(secondaryContainer = Color(0xFF90D8FF))
        val darkContainer = Color(0xFF003549)
        val cases = listOf(
            brightContainers to setOf(TunnelMood.ACTIVE, TunnelMood.RECOVERING),
            brightContainers.copy(secondaryContainer = darkContainer) to setOf(TunnelMood.ACTIVE),
            brightContainers.copy(primaryContainer = darkContainer) to setOf(TunnelMood.RECOVERING),
        )
        for ((colors, dimmed) in cases) {
            val containers = mapOf(
                TunnelMood.ACTIVE to colors.primaryContainer,
                TunnelMood.RECOVERING to colors.secondaryContainer,
            )
            for ((mood, container) in containers) {
                val palette = tunnelPalette(colors, dark = true, mood)
                val expected = if (mood in dimmed) lerp(colors.surfaceContainer, container, 0.27f) else container
                assertEquals(expected, palette.backdrop)
                assertContrast(palette.face, palette.backdrop, 3f)
                assertContrast(palette.face, palette.edge, 3f)
            }
        }
        val fallback = tunnelPalette(DarkColors, dark = true, TunnelMood.ACTIVE)
        assertEquals(DarkColors.primaryContainer, fallback.backdrop)
        assertContrast(fallback.face, fallback.backdrop, 3f)
        assertContrast(fallback.face, fallback.edge, 3f)
    }

    @Test
    fun darkTunnelUsesDistinctPalettesForAllMoods() {
        val colors = CyanDark.copy(secondaryContainer = Color(0xFF003549))
        val palettes = TunnelMood.entries.associateWith { tunnelPalette(colors, dark = true, it) }
        assertEquals(3, palettes.values.toSet().size)
        val off = palettes.getValue(TunnelMood.OFF)
        assertEquals(colors.surfaceContainer, off.backdrop)
        assertEquals(colors.outline, off.face)
        assertEquals(colors.outlineVariant, off.middle)
    }

    @Test
    fun lightTunnelRetainsOriginalActiveColors() {
        for (colors in listOf(CyanLight, LightColors)) {
            val palette = tunnelPalette(colors, dark = false, TunnelMood.ACTIVE)
            assertEquals(colors.primaryContainer, palette.backdrop)
            assertEquals(lerp(colors.primary, colors.primaryContainer, 0.19f), palette.face)
            assertEquals(lerp(colors.primary, colors.onPrimaryContainer, 0.25f), palette.edge)
        }
    }

    @Test
    fun expandedPeerKeepsTextAndActivePathReadable() {
        for ((colors, dark) in listOf(CyanDark to true, DarkColors to true, CyanLight to false, LightColors to false)) {
            val fill = expandedPeerFill(colors, dark)
            assertContrast(colors.onSurface, fill, 4.5f)
            assertContrast(colors.onSurfaceVariant, fill, 4.5f)
            assertContrast(colors.primary, fill, 3f)
            assertContrast(colors.onPrimary, colors.primary, 4.5f)
        }
    }

    private fun assertContrast(first: Color, second: Color, minimum: Float) {
        val a = first.luminance()
        val b = second.luminance()
        val ratio = (maxOf(a, b) + 0.05f) / (minOf(a, b) + 0.05f)
        assertTrue("Expected contrast of at least $minimum, got $ratio", ratio >= minimum)
    }
}

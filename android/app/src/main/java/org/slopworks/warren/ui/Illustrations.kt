package org.slopworks.warren.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.updateTransition
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.GenericShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.unit.dp
import org.slopworks.warren.R

private enum class TunnelMood { ACTIVE, OFF, RECOVERING }

private val ActiveFrame = GenericShape { size, _ ->
    val w = size.width
    val h = size.height
    moveTo(0f, 0.54f * h)
    cubicTo(0f, 0.17f * h, 0.22f * w, 0f, 0.46f * w, 0f)
    cubicTo(0.74f * w, 0f, w, 0.17f * h, w, 0.49f * h)
    cubicTo(w, 0.82f * h, 0.82f * w, h, 0.55f * w, h)
    cubicTo(0.25f * w, h, 0f, 0.84f * h, 0f, 0.54f * h)
    close()
}

@Composable
internal fun TunnelIllustration(status: WarrenVpnStatus) {
    val mood = when (status) {
        WarrenVpnStatus.OFF, WarrenVpnStatus.DISCONNECTING -> TunnelMood.OFF
        WarrenVpnStatus.CONNECTING, WarrenVpnStatus.RECOVERING -> TunnelMood.RECOVERING
        WarrenVpnStatus.CONNECTED -> TunnelMood.ACTIVE
    }
    val colors = MaterialTheme.colorScheme
    val dark = isSystemInDarkTheme()
    val frame = when (mood) {
        TunnelMood.OFF -> RoundedCornerShape(64.dp)
        TunnelMood.RECOVERING -> RoundedCornerShape(65.dp, 90.dp, 65.dp, 90.dp)
        TunnelMood.ACTIVE -> ActiveFrame
    }
    val backdrop by animateColorAsState(
        when (mood) {
            TunnelMood.OFF -> colors.surfaceContainer
            TunnelMood.RECOVERING -> colors.secondaryContainer
            TunnelMood.ACTIVE -> colors.primaryContainer
        },
        label = "Tunnel backdrop",
    )
    val transition = updateTransition(mood, label = "Tunnel")
    val spread by transition.animateFloat(label = "Arch spacing") { if (it == TunnelMood.RECOVERING) 1f else 0f }
    val packetX by transition.animateFloat(label = "Packet position X") {
        when (it) {
            TunnelMood.ACTIVE -> 121f
            TunnelMood.RECOVERING -> 93f
            TunnelMood.OFF -> 77f
        }
    }
    val packetY by transition.animateFloat(label = "Packet position Y") {
        when (it) {
            TunnelMood.ACTIVE -> 124f
            TunnelMood.RECOVERING -> 138f
            TunnelMood.OFF -> 145f
        }
    }
    val off = mood == TunnelMood.OFF
    val primary = colors.primary
    val mixed = lerp(primary, colors.primaryContainer, if (dark) 0.32f else 0.52f)
    val face = if (off) colors.outline else lerp(primary, colors.primaryContainer, if (dark) 0.12f else 0.19f)
    val middle = if (off) colors.outlineVariant else mixed
    val back = if (off) colors.surfaceContainerHigh else lerp(mixed, colors.primaryContainer, 0.5f)
    val edge = when {
        off -> colors.outline
        dark -> lerp(colors.primaryContainer, primary, 0.33f)
        else -> lerp(primary, colors.onPrimaryContainer, 0.25f)
    }
    val line = if (off) colors.outlineVariant else lerp(primary, colors.outline, 0.35f)
    val shadow = if (off) colors.onSurface else colors.onPrimaryContainer
    val packet = if (off) colors.outline else if (dark) colors.tertiary else colors.tertiaryContainer

    Canvas(
        Modifier.widthIn(max = 294.dp).fillMaxWidth().aspectRatio(1.48f)
            .clip(frame).background(backdrop),
    ) {
        val scale = minOf(size.width / 330f, size.height / 170f)
        withTransform({
            translate((size.width - 330f * scale) / 2f, (size.height - 170f * scale) / 2f)
            scale(scale, scale, pivot = Offset.Zero)
        }) {
            tunnelGround(line, dashed = mood != TunnelMood.ACTIVE, off = off)
            val frontShift = if (off) 7f else 7f * spread
            tunnelArch(206f + 17f * spread, 96f, 41f, 19f, back, edge, shadow, off)
            tunnelArch(168f + 7f * spread, 114f, 45f, 22f, middle, edge, shadow, off)
            tunnelArch(124f - frontShift, 135f, 49f, 23f, face, edge, shadow, off)
            val radius = if (off) 7.5f else 10f
            drawOval(
                shadow.copy(alpha = 0.14f),
                topLeft = Offset(packetX + 3f - radius, packetY + radius - 4f),
                size = Size(radius * 2.2f, 6f),
            )
            drawCircle(packet, radius, Offset(packetX, packetY))
            drawCircle(Color.White.copy(alpha = 0.22f), radius * 0.28f, Offset(packetX - 2f, packetY - 3f))
        }
    }
}

private fun DrawScope.tunnelGround(line: Color, dashed: Boolean, off: Boolean) {
    // The cable and the dots lie on the same isometric ground plane.
    for (i in -9..13) {
        for (j in -9..9) {
            val x = 164f + i * 12f + j * 10f
            val y = 102f + i * 3.4f - j * 5.8f
            val dx = (x - 166f) / 162f
            val dy = (y - 99f) / 60f
            val radius = dx * dx + dy * dy
            if (radius < 1f) drawCircle(line.copy(alpha = (1f - radius) * 0.34f), 0.8f, Offset(x, y))
        }
    }
    val cable = Path().apply {
        moveTo(5f, 124f)
        cubicTo(36f, 117f, 48f, 154f, 84f, 146f)
        cubicTo(105f, 143f, 107f, 139f, 124f, 130f)
        lineTo(233f, 80f)
        cubicTo(259f, 65f, 271f, 69f, 283f, 75f)
        cubicTo(297f, 80f, 305f, 80f, 324f, 74f)
    }
    drawPath(
        cable, line, alpha = if (off) 0.6f else 0.95f,
        style = Stroke(2f, cap = StrokeCap.Round, pathEffect = if (dashed) CableDashes else null),
    )
    drawCircle(line, 2.7f, Offset(12f, 124f))
    drawCircle(line, 3f, Offset(318f, 76f))
}

private val CableDashes = PathEffect.dashPathEffect(floatArrayOf(2.5f, 5.5f))

private fun DrawScope.tunnelArch(
    x: Float,
    y: Float,
    radius: Float,
    stem: Float,
    face: Color,
    edge: Color,
    shadow: Color,
    off: Boolean,
) {
    rotate(9f, pivot = Offset(x + 7f, y - 1f)) {
        drawOval(
            shadow.copy(alpha = if (off) 0.06f else 0.11f),
            topLeft = Offset(x - radius, y - 9f),
            size = Size(2f * radius + 14f, 16f),
        )
    }
    val arch = archFace(radius, stem)
    for (depth in 10 downTo 1) {
        translate(x + depth, y - depth * 0.53f) { drawPath(arch, edge) }
    }
    translate(x, y) { drawPath(arch, face) }
}

private fun archFace(outer: Float, stem: Float): Path {
    val inner = outer - 14f
    val outerTangent = outer * 0.55228475f
    val innerTangent = inner * 0.55228475f
    // Project each point with the same shear as the arch legs.
    fun y(x: Float, height: Float) = height + x * 0.17f
    return Path().apply {
        moveTo(-outer, y(-outer, 0f))
        lineTo(-outer, y(-outer, -stem))
        cubicTo(-outer, y(-outer, -stem - outerTangent), -outerTangent, y(-outerTangent, -stem - outer), 0f, -stem - outer)
        cubicTo(outerTangent, y(outerTangent, -stem - outer), outer, y(outer, -stem - outerTangent), outer, y(outer, -stem))
        lineTo(outer, y(outer, 0f))
        lineTo(inner, y(inner, 0f))
        lineTo(inner, y(inner, -stem))
        cubicTo(inner, y(inner, -stem - innerTangent), innerTangent, y(innerTangent, -stem - inner), 0f, -stem - inner)
        cubicTo(-innerTangent, y(-innerTangent, -stem - inner), -inner, y(-inner, -stem - innerTangent), -inner, y(-inner, -stem))
        lineTo(-inner, y(-inner, 0f))
        close()
    }
}

@Composable
internal fun EnrollmentIllustration() {
    val colors = MaterialTheme.colorScheme
    Box(
        Modifier.widthIn(max = 294.dp).fillMaxWidth().aspectRatio(1.48f)
            .clip(RoundedCornerShape(74.dp, 28.dp, 74.dp, 28.dp))
            .background(colors.primaryContainer),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val ring = colors.primary.copy(alpha = 0.24f)
            rotate(-30f) {
                drawOval(ring, Offset(size.width * 0.04f, size.height * 0.05f), size * 0.91f, style = Stroke(1.dp.toPx()))
                drawOval(ring, Offset(-size.width * 0.09f, -size.height * 0.06f), size * 1.14f, style = Stroke(1.dp.toPx()))
            }
        }
        EnrollmentTicket(
            modifier = Modifier.align(Alignment.Center).padding(end = 65.dp, bottom = 17.dp).rotate(-17f),
            color = colors.primary,
            ink = colors.onPrimary,
            icon = R.drawable.warren_ui_arch,
            iconSize = 58,
        )
        val dark = isSystemInDarkTheme()
        EnrollmentTicket(
            modifier = Modifier.align(Alignment.Center).padding(start = 69.dp, top = 21.dp).rotate(14f),
            color = if (dark) colors.tertiary else colors.tertiaryContainer,
            ink = if (dark) colors.onTertiary else colors.onTertiaryContainer,
            icon = R.drawable.warren_ui_qr,
            iconSize = 66,
        )
    }
}

@Composable
private fun EnrollmentTicket(modifier: Modifier, color: Color, ink: Color, icon: Int, iconSize: Int) {
    Surface(
        modifier = modifier.size(width = 99.dp, height = 120.dp),
        color = color,
        contentColor = ink,
        shape = RoundedCornerShape(20.dp),
        shadowElevation = 4.dp,
    ) {
        Box(contentAlignment = Alignment.Center) {
            WarrenIcon(icon, Modifier.size(iconSize.dp))
        }
    }
}

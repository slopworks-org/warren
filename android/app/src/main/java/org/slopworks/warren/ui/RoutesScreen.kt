package org.slopworks.warren.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.GenericShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.layout.layout
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import org.slopworks.warren.R
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

@Composable
internal fun RoutesScreen(routes: WarrenRoutes, onBack: () -> Unit) {
    val peers = (routes as? WarrenRoutes.Ready)?.peers.orEmpty()
    var expandedId by rememberSaveable { mutableStateOf<String?>(null) }
    LaunchedEffect(routes) {
        if (routes != WarrenRoutes.Loading && peers.none { it.id == expandedId && it.path != WarrenPath.UNAVAILABLE }) {
            expandedId = null
        }
    }
    Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally) {
        BackBar(onBack)
        LazyColumn(
            Modifier.widthIn(max = 560.dp).fillMaxWidth().padding(horizontal = 15.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            item {
                Text(
                    stringResource(R.string.warren_ui_routes),
                    Modifier.padding(start = 5.dp, top = 16.dp, bottom = 20.dp).semantics { heading() },
                    style = MaterialTheme.typography.headlineLarge,
                )
            }
            if (peers.isEmpty()) {
                item {
                    val message = when (routes) {
                        WarrenRoutes.Loading -> R.string.warren_ui_routes_loading
                        WarrenRoutes.Unavailable -> R.string.warren_ui_routes_unavailable
                        is WarrenRoutes.Ready -> R.string.warren_ui_routes_empty
                    }
                    Text(
                        stringResource(message),
                        Modifier.padding(horizontal = 5.dp).semantics { liveRegion = LiveRegionMode.Polite },
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            itemsIndexed(peers, key = { _, peer -> peer.id }) { index, peer ->
                val top = if (index == 0) 26.dp else 7.dp
                val bottom = if (index == peers.lastIndex) 26.dp else 7.dp
                val expanded = peer.id == expandedId && peer.path != WarrenPath.UNAVAILABLE
                PeerCard(peer, expanded, RoundedCornerShape(top, top, bottom, bottom)) {
                    expandedId = if (expanded) null else peer.id
                }
            }
        }
    }
}

internal fun expandedPeerFill(colors: ColorScheme, dark: Boolean): Color =
    lerp(colors.surfaceContainerHigh, colors.primary, if (dark) 0.08f else 0.06f)

@Composable
private fun PeerCard(peer: WarrenPeer, expanded: Boolean, shape: Shape, onToggle: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    val dark = isSystemInDarkTheme()
    val fill = if (expanded) expandedPeerFill(colors, dark) else colors.surfaceContainer
    val border = if (expanded) BorderStroke(1.dp, colors.primary.copy(alpha = if (dark) 0.28f else 0.24f)) else null
    val canExpand = peer.path != WarrenPath.UNAVAILABLE
    Surface(shape = shape, color = fill, contentColor = colors.onSurface, border = border) {
        Column {
            if (canExpand) {
                val description = stringResource(if (expanded) R.string.warren_ui_expanded else R.string.warren_ui_collapsed)
                Surface(
                    onClick = onToggle,
                    modifier = Modifier.semantics { stateDescription = description },
                    color = Color.Transparent,
                    contentColor = colors.onSurface,
                ) {
                    PeerHeader(peer, expanded)
                }
            } else {
                PeerHeader(peer, expanded = false)
            }
            if (expanded) {
                Box(Modifier.fillMaxWidth().padding(bottom = 12.dp), contentAlignment = Alignment.Center) {
                    PathDiagram(peer.path)
                }
            }
        }
    }
}

@Composable
private fun PeerHeader(peer: WarrenPeer, expanded: Boolean) {
    val colors = MaterialTheme.colorScheme
    val dark = isSystemInDarkTheme()
    val subtitle = when (peer.path) {
        WarrenPath.DIRECT -> R.string.warren_ui_direct
        WarrenPath.DIRECT_WIFI -> R.string.warren_ui_direct_wifi
        WarrenPath.RELAY -> R.string.warren_ui_relay
        WarrenPath.UNAVAILABLE -> R.string.warren_ui_path_unavailable
    }
    Row(
        Modifier.fillMaxWidth().heightIn(min = 65.dp).padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        val tile = if (expanded) colors.primary.copy(alpha = if (dark) 0.18f else 0.14f) else colors.surfaceContainerHigh
        Surface(shape = RoundedCornerShape(13.dp), color = tile, contentColor = if (expanded) colors.primary else colors.onSurfaceVariant) {
            Box(Modifier.size(37.dp), contentAlignment = Alignment.Center) {
                WarrenIcon(R.drawable.warren_ui_storage, Modifier.size(21.dp))
            }
        }
        Column(Modifier.weight(1f)) {
            Text(peer.name ?: peer.address, style = MaterialTheme.typography.titleMedium)
            val path = stringResource(subtitle)
            val detail = if (peer.name == null) path else stringResource(R.string.warren_ui_route_detail, peer.address, path)
            Text(detail, color = colors.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        }
        if (peer.path != WarrenPath.UNAVAILABLE) {
            val angle by animateFloatAsState(if (expanded) 180f else 0f, label = "Route chevron")
            WarrenIcon(
                R.drawable.warren_ui_expand,
                Modifier.size(22.dp).rotate(angle),
                tint = if (expanded) colors.primary else colors.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PathDiagram(path: WarrenPath) {
    val relay = path == WarrenPath.RELAY
    val colors = MaterialTheme.colorScheme
    val live = colors.primary
    val dark = isSystemInDarkTheme()
    val idle = colors.onSurfaceVariant.copy(alpha = if (dark) 0.40f else 0.42f)
    val packet = if (dark) colors.tertiary else colors.tertiaryContainer
    Box(Modifier.widthIn(max = 270.dp).fillMaxWidth().height(152.dp)) {
        Canvas(Modifier.fillMaxSize()) {
            val left = size.width * 0.15f
            val right = size.width * 0.85f
            val middle = size.width / 2f
            val top = 26.dp.toPx()
            val base = 120.dp.toPx()
            val curve = Path().apply {
                moveTo(left, base)
                cubicTo(size.width * 0.27f, base - 8.dp.toPx(), size.width * 0.27f, top + 16.dp.toPx(), middle, top)
                cubicTo(size.width * 0.73f, top + 16.dp.toPx(), size.width * 0.73f, base - 8.dp.toPx(), right, base)
            }
            val activeStroke = Stroke(3.4.dp.toPx(), cap = StrokeCap.Round)
            val dashes = PathEffect.dashPathEffect(floatArrayOf(3.dp.toPx(), 5.dp.toPx()))
            val idleStroke = Stroke(1.6.dp.toPx(), cap = StrokeCap.Round, pathEffect = dashes)
            drawPath(curve, if (relay) live else idle, style = if (relay) activeStroke else idleStroke)
            drawLine(
                if (relay) idle else live, Offset(left, base), Offset(right, base),
                strokeWidth = if (relay) idleStroke.width else activeStroke.width,
                cap = StrokeCap.Round, pathEffect = if (relay) dashes else null,
            )
            val dot = if (relay) Offset(size.width * 0.324f, 57.dp.toPx()) else Offset(middle, base)
            drawCircle(colors.primary, 5.1.dp.toPx(), dot)
            drawCircle(packet, 3.8.dp.toPx(), dot)
        }
        RouteNode(
            R.drawable.warren_ui_cloud, active = relay, shape = RoundedCornerShape(12.dp),
            modifier = Modifier.align(Alignment.TopCenter).offset(y = 8.dp).size(36.dp), small = true,
        )
        RouteNode(
            R.drawable.warren_ui_phone, active = true, shape = RoundedCornerShape(15.dp),
            modifier = Modifier.diagramEndpoint(0.15f).offset(y = 98.dp).size(43.dp),
        )
        RouteNode(
            R.drawable.warren_ui_storage, active = true, shape = PeerNodeShape,
            modifier = Modifier.diagramEndpoint(0.85f).offset(y = 98.dp).size(43.dp),
        )
    }
}

private fun Modifier.diagramEndpoint(fraction: Float) = layout { measurable, constraints ->
    val node = measurable.measure(constraints)
    layout(constraints.maxWidth, node.height) {
        node.place((constraints.maxWidth * fraction - node.width / 2f).toInt(), 0)
    }
}

private val PeerNodeShape = GenericShape { size, _ ->
    // A rounded eight-lobed node distinguishes the peer from the phone and the relay.
    repeat(48) { step ->
        val angle = step * 2 * PI / 48
        val radius = 0.455 + 0.043 * cos(8 * angle)
        val x = size.width * (0.5 + radius * cos(angle)).toFloat()
        val y = size.height * (0.5 + radius * sin(angle)).toFloat()
        if (step == 0) moveTo(x, y) else lineTo(x, y)
    }
    close()
}

@Composable
private fun RouteNode(icon: Int, active: Boolean, shape: Shape, modifier: Modifier, small: Boolean = false) {
    val colors = MaterialTheme.colorScheme
    val dark = isSystemInDarkTheme()
    Surface(
        modifier = modifier,
        shape = shape,
        color = if (active) colors.primary else colors.onSurface.copy(alpha = if (dark) 0.10f else 0.08f),
        contentColor = if (active) colors.onPrimary else colors.onSurfaceVariant,
    ) {
        Box(contentAlignment = Alignment.Center) {
            WarrenIcon(icon, Modifier.size(if (small) 19.dp else 22.dp))
        }
    }
}

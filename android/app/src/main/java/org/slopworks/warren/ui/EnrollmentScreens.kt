package org.slopworks.warren.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.slopworks.warren.R

@Composable
internal fun EnrollmentScreen(state: WarrenUiState.Enrollment, onAction: (WarrenAction) -> Unit) {
    var showHelp by rememberSaveable { mutableStateOf(false) }
    val cancel = { onAction(WarrenAction.CANCEL_ENROLLMENT) }
    BackHandler(enabled = state.replacing && !state.pending) { if (!state.busy) cancel() }
    Column(Modifier.fillMaxSize()) {
        BrandBar {
            IconButton(onClick = { showHelp = true }) {
                WarrenIcon(R.drawable.warren_ui_info, label = stringResource(R.string.warren_ui_qr_help))
            }
        }
        val title = if (state.replacing) R.string.warren_ui_replace_profile else R.string.warren_ui_add_phone
        Landing(stringResource(title), illustration = { EnrollmentIllustration() }) {
            state.error?.let { ErrorMessage(it, Modifier.padding(bottom = 4.dp)) }
            val label = when {
                state.busy -> R.string.warren_ui_enrolling
                state.pending -> R.string.warren_ui_retry_enrollment
                else -> R.string.warren_ui_scan
            }
            MainAction(
                label = stringResource(label),
                icon = R.drawable.warren_ui_scan,
                onClick = { onAction(if (state.pending) WarrenAction.RETRY_ENROLLMENT else WarrenAction.SCAN_QR) },
                enabled = !state.busy,
            )
            if (!state.pending) {
                SecondaryAction(
                    label = stringResource(R.string.warren_ui_choose_photo),
                    icon = R.drawable.warren_ui_photos,
                    onClick = { onAction(WarrenAction.CHOOSE_PHOTO) },
                    enabled = !state.busy,
                )
            }
            if (state.replacing || state.pending) {
                SecondaryAction(stringResource(R.string.warren_ui_cancel), R.drawable.warren_ui_close, cancel,
                    enabled = !state.busy)
            }
        }
    }
    if (showHelp) {
        WarrenSheet(stringResource(R.string.warren_ui_qr_help), onDismiss = { showHelp = false }) {
            Text(
                stringResource(R.string.warren_ui_qr_help_body),
                modifier = Modifier.padding(end = 6.dp, bottom = 8.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
internal fun ScannerScreen(
    state: WarrenUiState.Scanner,
    onAction: (WarrenAction) -> Unit,
    cameraPreview: @Composable () -> Unit,
) {
    val close = { onAction(WarrenAction.CLOSE_SCANNER) }
    BackHandler(onBack = close)

    Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally) {
        BackBar(onBack = close, title = stringResource(R.string.warren_ui_qr_code))
        BoxWithConstraints(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
            val scroll = maxHeight < 360.dp || LocalDensity.current.fontScale > 1.4f
            val body = if (scroll) Modifier.verticalScroll(rememberScrollState()) else Modifier
            Column(
                Modifier.widthIn(max = 560.dp).fillMaxWidth().then(body)
                    .padding(start = 13.dp, end = 13.dp, bottom = 10.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                state.error?.let { ErrorMessage(it) }
                ScannerPreview(
                    state = state,
                    onToggleTorch = { onAction(WarrenAction.TOGGLE_TORCH) },
                    modifier = if (scroll) Modifier.height(240.dp) else Modifier.weight(1f),
                    cameraPreview = cameraPreview,
                )
                MainAction(
                    label = stringResource(R.string.warren_ui_choose_photo),
                    icon = R.drawable.warren_ui_photos,
                    enabled = !state.busy,
                    onClick = { onAction(WarrenAction.CHOOSE_PHOTO) },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                        contentColor = MaterialTheme.colorScheme.onSurface,
                    ),
                )
            }
        }
    }
}

@Composable
private fun ScannerPreview(
    state: WarrenUiState.Scanner,
    onToggleTorch: () -> Unit,
    modifier: Modifier,
    cameraPreview: @Composable () -> Unit,
) {
    Box(
        modifier.fillMaxWidth().clip(RoundedCornerShape(27.dp)).background(Color(0xFF20232A)),
        contentAlignment = Alignment.Center,
    ) {
        Box(Modifier.matchParentSize()) { cameraPreview() }
        ScanCorners(Modifier.matchParentSize())
        state.torchEnabled?.let { enabled ->
            IconButton(
                onClick = onToggleTorch,
                enabled = !state.busy,
                modifier = Modifier.align(Alignment.TopEnd).padding(8.dp),
                colors = IconButtonDefaults.iconButtonColors(
                    containerColor = Color(0xCC20232A),
                    contentColor = Color.White,
                ),
            ) {
                WarrenIcon(
                    if (enabled) R.drawable.warren_ui_torch else R.drawable.warren_ui_torch_off,
                    label = stringResource(if (enabled) R.string.warren_ui_torch_off else R.string.warren_ui_torch_on),
                )
            }
        }
        if (state.busy) {
            Column(
                Modifier.clip(RoundedCornerShape(20.dp)).background(Color(0xE620232A))
                    .padding(horizontal = 20.dp, vertical = 16.dp)
                    .semantics { liveRegion = LiveRegionMode.Polite },
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                CircularProgressIndicator(Modifier.size(24.dp), color = Color.White)
                Text(stringResource(R.string.warren_ui_enrolling), color = Color.White)
            }
        }
    }
}

@Composable
private fun ScanCorners(modifier: Modifier) {
    Canvas(modifier) {
        val half = minOf(91.dp.toPx(), size.minDimension * 0.37f)
        val segment = half * 0.29f
        val radius = segment * 0.46f
        val x = center.x - half
        val y = center.y - half
        val corner = Path().apply {
            moveTo(x, y + segment)
            lineTo(x, y + radius)
            quadraticTo(x, y, x + radius, y)
            lineTo(x + segment, y)
        }
        repeat(4) { quarter ->
            rotate(quarter * 90f) {
                drawPath(corner, Color(0x80000000), style = Stroke(5.dp.toPx(), cap = StrokeCap.Round))
                drawPath(corner, Color.White, style = Stroke(3.dp.toPx(), cap = StrokeCap.Round))
            }
        }
    }
}

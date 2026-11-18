package org.slopworks.warren.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetValue
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.LineBreak
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import org.slopworks.warren.R

@Composable
internal fun WarrenIcon(
    icon: Int,
    modifier: Modifier = Modifier,
    label: String? = null,
    tint: Color = LocalContentColor.current,
) {
    Icon(
        painter = painterResource(icon),
        contentDescription = label,
        modifier = modifier,
        tint = tint,
    )
}

@Composable
internal fun BrandBar(action: @Composable () -> Unit = {}) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(start = 18.dp, end = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        WarrenIcon(R.drawable.warren_ui_arch, Modifier.size(28.dp), tint = MaterialTheme.colorScheme.primary)
        Text(stringResource(R.string.warren_ui_brand), style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.weight(1f))
        action()
    }
}

@Composable
internal fun BackBar(onBack: () -> Unit, title: String? = null) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(horizontal = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            WarrenIcon(R.drawable.warren_ui_back, label = stringResource(R.string.warren_ui_back))
        }
        if (title != null) {
            Text(title, Modifier.semantics { heading() }, style = MaterialTheme.typography.titleMedium)
        }
    }
}

@Composable
internal fun Landing(
    title: String,
    illustration: @Composable () -> Unit,
    dock: @Composable ColumnScope.() -> Unit,
) {
    BoxWithConstraints(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        val viewportHeight = maxHeight
        Column(
            Modifier.widthIn(max = 480.dp).fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .heightIn(min = viewportHeight)
                .padding(start = 20.dp, end = 20.dp, bottom = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.weight(1f))
            illustration()
            Text(
                title,
                Modifier.padding(top = 23.dp, bottom = 8.dp).semantics {
                    heading()
                    liveRegion = LiveRegionMode.Polite
                },
                textAlign = TextAlign.Center,
                style = MaterialTheme.typography.headlineLarge.copy(lineBreak = LineBreak.Heading),
            )
            Spacer(Modifier.weight(1f))
            Column(
                Modifier.fillMaxWidth().padding(top = 12.dp).heightIn(min = 106.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                dock()
            }
        }
    }
}

@Composable
internal fun MainAction(
    label: String,
    icon: Int,
    onClick: () -> Unit,
    enabled: Boolean = true,
    colors: ButtonColors = ButtonDefaults.buttonColors(),
) {
    Button(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
        enabled = enabled,
        shapes = ButtonDefaults.shapes(),
        colors = colors,
    ) {
        WarrenIcon(icon, Modifier.size(20.dp))
        Text(label, Modifier.padding(start = 8.dp), textAlign = TextAlign.Center)
    }
}

@Composable
internal fun SecondaryAction(label: String, icon: Int, onClick: () -> Unit, enabled: Boolean = true) {
    TextButton(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        enabled = enabled,
    ) {
        WarrenIcon(icon, Modifier.size(20.dp))
        Text(label, Modifier.padding(start = 8.dp), textAlign = TextAlign.Center)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun WarrenSheet(title: String, onDismiss: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberBottomSheetState(
            initialValue = SheetValue.Hidden,
            enabledValues = setOf(SheetValue.Hidden, SheetValue.Expanded),
        ),
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState())
                .padding(start = 18.dp, end = 12.dp, bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title,
                    Modifier.weight(1f).semantics { heading() },
                    style = MaterialTheme.typography.titleLarge,
                )
                IconButton(onClick = onDismiss) {
                    WarrenIcon(R.drawable.warren_ui_close, label = stringResource(R.string.warren_ui_close))
                }
            }
            content()
        }
    }
}

@Composable
internal fun ErrorMessage(error: WarrenError, modifier: Modifier = Modifier) {
    val message = when (error) {
        WarrenError.CAMERA_DENIED -> R.string.warren_ui_error_camera_denied
        WarrenError.CAMERA_UNAVAILABLE -> R.string.warren_ui_error_camera_unavailable
        WarrenError.PHOTO_UNREADABLE -> R.string.warren_ui_error_photo_unreadable
        WarrenError.QR_NOT_FOUND -> R.string.warren_ui_error_qr_not_found
        WarrenError.INVALID_CODE -> R.string.warren_ui_error_invalid_code
        WarrenError.EXPIRED_CODE -> R.string.warren_ui_error_expired_code
        WarrenError.ENROLLMENT_FAILED -> R.string.warren_ui_error_enrollment_failed
        WarrenError.SERVER_UNREACHABLE -> R.string.warren_ui_error_server_unreachable
        WarrenError.SERVER_UPGRADE -> R.string.warren_ui_error_server_upgrade
        WarrenError.VPN_DENIED -> R.string.warren_ui_error_vpn_denied
        WarrenError.VPN_FAILED -> R.string.warren_ui_error_vpn_failed
        WarrenError.TILE_FAILED -> R.string.warren_ui_error_tile_failed
    }
    val colors = MaterialTheme.colorScheme
    Surface(
        modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
        shape = RoundedCornerShape(12.dp),
        color = colors.errorContainer,
        contentColor = colors.onErrorContainer,
    ) {
        Box(Modifier.padding(horizontal = 13.dp, vertical = 10.dp)) {
            Text(stringResource(message), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

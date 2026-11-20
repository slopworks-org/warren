package org.slopworks.warren.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.slopworks.warren.R

private enum class ConnectionSheet { ACTIONS, DETAILS }

@Composable
internal fun HomeScreen(
    state: WarrenUiState.Home,
    onAction: (WarrenAction) -> Unit,
    onRoutes: () -> Unit,
) {
    var sheet by rememberSaveable { mutableStateOf<ConnectionSheet?>(null) }
    var confirmReplacement by rememberSaveable { mutableStateOf(false) }
    val status = state.status
    val title = when (status) {
        WarrenVpnStatus.OFF -> R.string.warren_ui_off
        WarrenVpnStatus.CONNECTING -> R.string.warren_ui_connecting
        WarrenVpnStatus.CONNECTED -> R.string.warren_ui_connected
        WarrenVpnStatus.RECOVERING -> R.string.warren_ui_recovering
        WarrenVpnStatus.DISCONNECTING -> R.string.warren_ui_disconnecting
    }

    Column(Modifier.fillMaxSize()) {
        BrandBar {
            if (state.details != null || state.canAddTile) {
                IconButton(onClick = { sheet = ConnectionSheet.ACTIONS }) {
                    WarrenIcon(
                        R.drawable.warren_ui_more,
                        label = stringResource(R.string.warren_ui_connection_actions),
                    )
                }
            }
        }
        Landing(stringResource(title), illustration = { TunnelIllustration(status) }) {
            state.error?.let { ErrorMessage(it, Modifier.padding(bottom = 4.dp)) }
            val off = status == WarrenVpnStatus.OFF
            val connecting = status == WarrenVpnStatus.CONNECTING
            val disconnecting = status == WarrenVpnStatus.DISCONNECTING
            MainAction(
                label = stringResource(if (off || connecting) R.string.warren_ui_connect else R.string.warren_ui_disconnect),
                icon = R.drawable.warren_ui_power,
                onClick = { onAction(if (off) WarrenAction.CONNECT else WarrenAction.DISCONNECT) },
                enabled = !connecting && !disconnecting,
                colors = if (status == WarrenVpnStatus.RECOVERING) {
                    ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.secondary,
                        contentColor = MaterialTheme.colorScheme.onSecondary,
                    )
                } else {
                    ButtonDefaults.buttonColors()
                },
            )
            if (status == WarrenVpnStatus.CONNECTED) {
                SecondaryAction(stringResource(R.string.warren_ui_routes), R.drawable.warren_ui_lan, onRoutes)
            }
        }
    }

    val closeSheet = { sheet = null }
    when (sheet) {
        ConnectionSheet.ACTIONS -> if (state.details != null || state.canAddTile) {
            WarrenSheet(stringResource(R.string.warren_ui_connection), closeSheet) {
                if (state.details != null) {
                    ActionRow(R.drawable.warren_ui_info, stringResource(R.string.warren_ui_details)) {
                        sheet = ConnectionSheet.DETAILS
                    }
                    ActionRow(R.drawable.warren_ui_qr, stringResource(R.string.warren_ui_replace_profile)) {
                        closeSheet()
                        confirmReplacement = true
                    }
                }
                if (state.canAddTile) {
                    ActionRow(R.drawable.warren_ui_tile, stringResource(R.string.warren_ui_add_tile)) {
                        closeSheet()
                        onAction(WarrenAction.ADD_TILE)
                    }
                }
            }
        }

        ConnectionSheet.DETAILS -> state.details?.let { ConnectionDetailsSheet(it, closeSheet) }
        null -> Unit
    }
    if (confirmReplacement) {
        AlertDialog(
            onDismissRequest = { confirmReplacement = false },
            title = { Text(stringResource(R.string.warren_ui_replace_profile)) },
            text = { Text(stringResource(R.string.warren_ui_replace_profile_detail)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmReplacement = false
                    onAction(WarrenAction.REPLACE_PROFILE)
                }) { Text(stringResource(R.string.warren_ui_replace_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmReplacement = false }) { Text(stringResource(R.string.warren_ui_cancel)) }
            },
        )
    }
}

@Composable
private fun ActionRow(icon: Int, title: String, onClick: () -> Unit) {
    Surface(onClick = onClick, shape = RoundedCornerShape(13.dp)) {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(13.dp),
        ) {
            WarrenIcon(icon, Modifier.size(22.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(title, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@Composable
private fun ConnectionDetailsSheet(details: WarrenConnectionDetails, onDismiss: () -> Unit) {
    WarrenSheet(stringResource(R.string.warren_ui_connection_details), onDismiss) {
        DetailRow(R.drawable.warren_ui_cloud, stringResource(R.string.warren_ui_server), details.server)
        if (details.splitTunnel) {
            DetailRow(
                R.drawable.warren_ui_lan,
                stringResource(R.string.warren_ui_resources),
                stringResource(R.string.warren_ui_through_vpn),
            )
            DetailRow(
                R.drawable.warren_ui_internet,
                stringResource(R.string.warren_ui_other_internet),
                stringResource(R.string.warren_ui_bypasses_vpn),
            )
        }
        if (details.reconnects) {
            DetailRow(
                R.drawable.warren_ui_sync,
                stringResource(R.string.warren_ui_auto_connect),
                stringResource(R.string.warren_ui_auto_connect_detail),
            )
        }
    }
}

@Composable
private fun DetailRow(icon: Int, title: String, description: String) {
    val colors = MaterialTheme.colorScheme
    Surface(shape = RoundedCornerShape(14.dp), color = colors.surfaceContainer) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(shape = RoundedCornerShape(13.dp), color = colors.surfaceContainerHigh) {
                Box(Modifier.size(37.dp), contentAlignment = Alignment.Center) {
                    WarrenIcon(icon, Modifier.size(20.dp), tint = colors.onSurfaceVariant)
                }
            }
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(description, color = colors.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

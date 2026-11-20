package org.slopworks.warren.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import org.slopworks.warren.MainActivity
import org.slopworks.warren.R
import org.slopworks.warren.agent.ProfileStore

internal class WarrenTile : TileService() {
    private val listener = TilePhaseListener(CoroutineScope(Dispatchers.Main.immediate), WarrenVpnService.status, ::render)

    override fun onStartListening() = listener.start()

    override fun onStopListening() = listener.stop()

    override fun onDestroy() {
        listener.stop()
        super.onDestroy()
    }

    override fun onClick() = unlockAndRun {
        val phase = WarrenVpnService.status.value.phase
        if (phase != Phase.OFF && phase != Phase.DISCONNECTING) {
            WarrenVpnService.disconnect(this)
        } else if (phase == Phase.OFF) {
            val enrollment = runCatching { ProfileStore(this).load() }.getOrNull()
            if (enrollment != null && VpnService.prepare(this) == null) {
                if (runCatching { WarrenVpnService.connect(this) }.isFailure) launchApp()
            } else {
                launchApp()
            }
        }
    }

    private fun render(phase: Phase) {
        qsTile?.apply {
            state = when (phase) {
                Phase.OFF -> Tile.STATE_INACTIVE
                Phase.DISCONNECTING -> Tile.STATE_UNAVAILABLE
                else -> Tile.STATE_ACTIVE
            }
            subtitle = getString(when (phase) {
                Phase.OFF -> R.string.status_off
                Phase.CONNECTING -> R.string.status_connecting
                Phase.CONNECTED -> R.string.status_connected
                Phase.RECOVERING -> R.string.status_recovering
                Phase.DISCONNECTING -> R.string.status_disconnecting
            })
            updateTile()
        }
    }

    // The Intent overload runs only on Android 12 and 13.
    @android.annotation.SuppressLint("StartActivityAndCollapseDeprecated")
    @Suppress("DEPRECATION")
    private fun launchApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            startActivityAndCollapse(intent)
        }
    }
}

internal class TilePhaseListener(
    private val scope: CoroutineScope,
    private val status: StateFlow<VpnStatus>,
    private val render: (Phase) -> Unit,
) {
    private var collection: Job? = null

    fun start() {
        if (collection?.isActive == true) return
        collection = scope.launch { status.map { it.phase }.distinctUntilChanged().collect(render) }
    }

    fun stop() {
        collection?.cancel()
        collection = null
    }
}

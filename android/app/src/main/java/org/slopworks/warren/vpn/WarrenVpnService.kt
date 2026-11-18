package org.slopworks.warren.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.slopworks.warren.MainActivity
import org.slopworks.warren.R
import org.slopworks.warren.agent.PendingEnrollment
import org.slopworks.warren.agent.Profile
import org.slopworks.warren.agent.ProfileStore

internal class WarrenVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private lateinit var store: ProfileStore
    private var running: Job? = null
    @Volatile private var generation = 0

    override fun onCreate() {
        super.onCreate()
        store = ProfileStore(this)
        instance = this
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.notification_channel_vpn), NotificationManager.IMPORTANCE_LOW),
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopByUser()
            return START_NOT_STICKY
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        startForeground(NOTIFICATION, notification(open))
        // A queued foreground start can run after the app replaces the profile.
        if (!runCatching { store.wantsVpn }.getOrDefault(false) || VpnService.prepare(this) != null) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if (running?.isActive == true) return START_STICKY
        val current = ++generation
        update(VpnStatus(Phase.CONNECTING))
        running = scope.launch {
            try {
                val session = TunnelSession(this@WarrenVpnService, store, open) {
                    if (generation == current) update(it)
                }
                var attempted = false
                getSystemService(ConnectivityManager::class.java).underlays().collectLatest { network ->
                    if (network == null) {
                        if (attempted) update(VpnStatus(Phase.RECOVERING))
                        return@collectLatest
                    }
                    val endpoints = HubEndpoints(network.network::getAllByName)
                    retryTunnel(
                        desired = { store.wantsVpn },
                        attempt = {
                            update(VpnStatus(if (attempted) Phase.RECOVERING else Phase.CONNECTING))
                            attempted = true
                            session.run(network, endpoints)
                        },
                        canRetry = {
                            val consent = VpnService.prepare(this@WarrenVpnService) == null
                            if (!consent) stopByUser(failed = true)
                            consent
                        },
                        wait = {
                            update(VpnStatus(Phase.RECOVERING, failed = true))
                            delay(it)
                        },
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                stopByUser(failed = true)
            }
        }
        return START_STICKY
    }

    private fun notification(open: PendingIntent): Notification {
        val stop = PendingIntent.getService(this, 0, Intent(this, javaClass).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_warren_vpn)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_vpn))
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, getString(R.string.notification_disconnect), stop).build())
            .setOngoing(true)
            .build()
    }

    private fun stopByUser(failed: Boolean = false) {
        try {
            store.wantsVpn = false
        } finally {
            stopTunnel(failed)
        }
    }

    private fun stopTunnel(failed: Boolean = false) {
        val current = ++generation
        val old = running
        update(VpnStatus(Phase.DISCONNECTING))
        old?.cancel()
        scope.launch {
            old?.join()
            if (generation == current) {
                update(VpnStatus(Phase.OFF, failed = failed))
                // Android may keep the service bound. The worker has already
                // stopped, regardless of how these lifecycle calls finish.
                runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                runCatching { stopSelf() }
            }
        }
    }

    override fun onRevoke() {
        scope.launch { stopByUser(failed = true) }
    }

    override fun onDestroy() {
        generation++
        scope.cancel()
        if (instance === this) {
            instance = null
            update(VpnStatus(Phase.OFF))
        }
        super.onDestroy()
    }

    private fun update(value: VpnStatus) {
        mutableStatus.value = value
    }

    companion object {
        private const val ACTION_STOP = "org.slopworks.warren.STOP_VPN"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION = 41
        // Activity, tile and service lifecycle callbacks run on the same
        // main thread and the VPN service uses the default app process.
        private var instance: WarrenVpnService? = null
        private val mutableStatus = MutableStateFlow(VpnStatus(Phase.OFF))
        val status = mutableStatus.asStateFlow()

        fun connect(context: Context) {
            check(VpnService.prepare(context) == null)
            val store = ProfileStore(context)
            store.wantsVpn = true
            try {
                restore(context)
            } catch (e: Exception) {
                store.wantsVpn = false
                throw e
            }
        }

        fun disconnect(context: Context) {
            instance?.let { it.stopByUser(); return }
            ProfileStore(context).wantsVpn = false
        }

        suspend fun replaceProfile(store: ProfileStore, pending: PendingEnrollment, profile: Profile) {
            TunnelSession.lifetime.replace(
                pause = { store.pauseForEnrollment(pending) },
                stopService = { instance?.stopTunnel() },
                commit = { store.completeEnrollment(pending, profile) },
            )
        }

        fun restore(context: Context) {
            if (ProfileStore(context).wantsVpn && VpnService.prepare(context) == null) {
                context.startForegroundService(Intent(context, WarrenVpnService::class.java))
            }
        }
    }
}

internal class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            runCatching { WarrenVpnService.restore(context) }
        }
    }
}

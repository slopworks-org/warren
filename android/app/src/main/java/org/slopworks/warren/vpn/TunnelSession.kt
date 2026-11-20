package org.slopworks.warren.vpn

import android.app.PendingIntent
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.OsConstants
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import org.slopworks.warren.agent.AgentClient
import org.slopworks.warren.agent.AgentException
import org.slopworks.warren.agent.AgentFailure
import org.slopworks.warren.agent.Ipv4
import org.slopworks.warren.agent.Peer
import org.slopworks.warren.agent.Profile
import org.slopworks.warren.agent.ProfileStore
import java.io.IOException

internal enum class Phase { OFF, CONNECTING, CONNECTED, RECOVERING, DISCONNECTING }
internal data class VpnStatus(
    val phase: Phase,
    val peers: List<PeerPath>? = null,
    val failed: Boolean = false,
    val routesLoading: Boolean = false,
)

internal class TunnelSession(
    private val service: WarrenVpnService,
    private val store: ProfileStore,
    private val pending: PendingIntent,
    private val publish: (VpnStatus) -> Unit,
) {
    suspend fun run(underlay: Underlay, endpoints: HubEndpoints) = lifetime.run {
        runSession(underlay, endpoints)
    }

    private suspend fun runSession(underlay: Underlay, endpoints: HubEndpoints) = withContext(Dispatchers.IO) {
        var profile = store.activeProfile() ?: return@withContext
        val ip = profile.config.address.ip
        var installed = profile.config
        val mtu = 1420
        val builder = service.Builder()
            .setSession("Warren")
            .setMtu(mtu)
            .addAddress(ip.inet(), profile.config.address.bits)
            .allowFamily(OsConstants.AF_INET6)
            .setConfigureIntent(pending)
            .setUnderlyingNetworks(arrayOf(underlay.network))
            .setMetered(false)
        profile.config.hub.allowed.forEach { route ->
            val network = Ipv4(route.ip.bits and (-1 shl (32 - route.bits)))
            builder.addRoute(network.inet(), route.bits)
        }
        val fd = checkNotNull(builder.establish()) { "VPN permission is unavailable" }.detachFd()
        check(WireGuard.open(fd, ip.bits, Ipv4.parse(installed.control.host).bits, installed.control.port))
        try {
            bindSockets(underlay)
            var hubConfig = hubUapi(profile, endpoints).also { installHub(it, endpoints) }
            val port = WireGuard.lanPort().also { check(it in 1..65535) }
            val emptyLan = "private_key=${profile.privateKey}\nreplace_peers=true\n"
            // The saved config gives us enough information to reach the control
            // listener. Only a live poll can authorize receiving or sending LAN traffic.
            check(WireGuard.setLan(emptyLan, "", 0))
            // Serialize publication with LAN replacement so the ticker cannot
            // publish obsolete proof after an ACL edit or during recovery.
            withContext(Dispatchers.IO.limitedParallelism(1)) {
                withLiveRoutes(
                    underlay.wifi,
                    { WireGuard.directPaths().lineSequence().toSet() },
                    publish,
                    disableForwarding = { WireGuard.setForwarding(false) },
                ) {
                    var first = true
                    var refresh = false
                    var failures = 0
                    while (currentCoroutineContext().isActive) {
                        val before = SystemClock.elapsedRealtime()
                        val wait = when {
                            first || refresh || failures > 0 -> 0
                            underlay.lan.isEmpty() -> 50
                            else -> 5
                        }
                        // Keep LAN polls shorter than the lease. Their deadline starts before
                        // the request and uses the same suspend-inclusive clock as native code.
                        val lanDeadline = if (underlay.lan.isEmpty()) 0L
                            else SystemClock.elapsedRealtimeNanos() + LAN_AUTHORIZATION_NANOS
                        val updated = try {
                            AgentClient.poll(profile.config, wait, underlay.lan, port, onForbidden = ::revoke)
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: IOException) {
                            if (e is AgentException && e.failure == AgentFailure.REVOKED) throw e
                            clear()
                            check(WireGuard.setLan(emptyLan, "", 0))
                            publish(VpnStatus(Phase.RECOVERING, failed = true))
                            // Give a working endpoint time to recover from a transient control failure.
                            // A candidate that has never reached control can yield immediately.
                            if (first || ++failures >= 3) {
                                endpoints.failed()
                                throw e
                            }
                            delay(1000L * failures)
                            continue
                        }
                        failures = 0
                        first = false
                        refresh = lanDeadline != 0L && SystemClock.elapsedRealtimeNanos() >= lanDeadline
                        if (refresh) continue
                        if (updated != null) {
                            profile = profile.withConfig(updated)
                            if (updated.address != installed.address || updated.hub.allowed != installed.hub.allowed ||
                                updated.control != installed.control
                            ) {
                                check(WireGuard.setLan(emptyLan, "", 0))
                                store.saveConfig(profile)
                                return@withLiveRoutes
                            }
                        }
                        WireGuard.setForwarding(true)
                        val peers = profile.config.eligibleLan(underlay.lan)
                        val directConfig = buildString {
                            append(emptyLan)
                            peers.forEach { peer ->
                                appendPeer(peer, peer.endpoint.toString())
                                appendLine("allowed_ip=${peer.allowed.single().ip.probeAddress()}/128")
                            }
                        }
                        val addresses = peers.joinToString("\n") { it.allowed.single().ip.toString() }
                        check(WireGuard.setLan(directConfig, addresses, lanDeadline))
                        if (!ready || updated != null) {
                            update(profile.config, peers)
                        }
                        if (updated != null) {
                            store.saveConfig(profile)
                            val candidate = hubUapi(profile, endpoints)
                            if (candidate != hubConfig) {
                                installHub(candidate, endpoints)
                                hubConfig = candidate
                                first = true
                            }
                            installed = updated
                        }
                        val elapsed = SystemClock.elapsedRealtime() - before
                        if (elapsed < 1000) delay(1000 - elapsed)
                    }
                }
            }
        } finally {
            WireGuard.close()
        }
    }

    companion object {
        private const val LAN_AUTHORIZATION_NANOS = 12_000_000_000L
        val lifetime = TunnelLifetime()
    }

    private fun bindSockets(underlay: Underlay) {
        for (mesh in listOf(false, true)) for (ipv6 in listOf(false, true)) {
            val fd = WireGuard.socket(mesh, ipv6)
            if (fd < 0) {
                if (!ipv6) error("WireGuard socket unavailable")
                continue
            }
            check(service.protect(fd))
            ParcelFileDescriptor.fromFd(fd).use { underlay.network.bindSocket(it.fileDescriptor) }
        }
    }

    private fun installHub(config: String, endpoints: HubEndpoints) {
        if (!WireGuard.setHub(config)) {
            endpoints.failed()
            error("WireGuard rejected hub configuration")
        }
    }

    private fun hubUapi(profile: Profile, endpoints: HubEndpoints): String {
        val peer = profile.config.hub
        val endpoint = endpoints.select(peer.endpoint).toString()
        return buildString {
            appendLine("private_key=${profile.privateKey}")
            appendLine("replace_peers=true")
            appendPeer(peer, endpoint)
        }
    }

    private fun StringBuilder.appendPeer(peer: Peer, endpoint: String) {
        appendLine("public_key=${peer.key}")
        appendLine("endpoint=$endpoint")
        appendLine("persistent_keepalive_interval=${peer.keepalive}")
        peer.allowed.forEach { appendLine("allowed_ip=$it") }
    }
}

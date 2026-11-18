package org.slopworks.warren.vpn

import org.slopworks.warren.agent.AgentConfig
import org.slopworks.warren.agent.Ipv4
import org.slopworks.warren.agent.Peer
import org.slopworks.warren.agent.Prefix
import org.slopworks.warren.agent.RoutePeer

internal data class PeerPath(val id: String, val address: String, val name: String?, val direct: Boolean, val wifi: Boolean)

internal fun AgentConfig.eligibleLan(underlay: List<Prefix>): List<Peer> = lan.filter { peer ->
    val endpoint = Ipv4.parse(peer.endpoint.host)
    underlay.any { it.contains(endpoint) && it.ip != endpoint }
}

internal class PeerRoutes(config: AgentConfig, eligibleLan: List<Peer>, directory: List<RoutePeer>? = config.routePeers) {
    private val eligible = eligibleLan.mapTo(mutableSetOf()) { it.allowed.single().ip }
    // Older servers only supply LAN candidates. Use the current eligible
    // candidates as a fallback and require live proof for them too.
    private val peers = directory ?: eligibleLan.map { RoutePeer(it.key, it.allowed.single().ip, null) }

    fun paths(proven: Set<String>, wifi: Boolean): List<PeerPath> = peers.map { peer ->
        val address = peer.address.toString()
        val direct = peer.address in eligible && address in proven
        PeerPath(peer.id, address, peer.name, direct, direct && wifi)
    }
}

// Config changes and proof ticks share the session's serial dispatcher.
internal class RoutePublication(
    private val wifi: Boolean,
    private val proven: () -> Set<String>,
    private val publish: (VpnStatus) -> Unit,
) {
    private var snapshot: PeerRoutes? = null
    val ready get() = snapshot != null

    fun clear() { snapshot = null }

    fun update(config: AgentConfig, peers: List<Peer>, directory: List<RoutePeer>?) {
        if (config.legacyRoutesMayBeTruncated || (config.routePage != null && directory == null)) {
            clear()
            publish(VpnStatus(Phase.CONNECTED, routesLoading = config.routePage != null))
        } else {
            snapshot = PeerRoutes(config, peers, directory ?: config.routePeers)
            tick()
        }
    }

    fun tick() {
        snapshot?.let { publish(VpnStatus(Phase.CONNECTED, it.paths(proven(), wifi))) }
    }
}

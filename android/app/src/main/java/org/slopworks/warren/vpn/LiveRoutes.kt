package org.slopworks.warren.vpn

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import org.slopworks.warren.agent.AgentClient
import org.slopworks.warren.agent.AgentConfig
import org.slopworks.warren.agent.AgentException
import org.slopworks.warren.agent.AgentFailure
import org.slopworks.warren.agent.Endpoint
import org.slopworks.warren.agent.Peer
import org.slopworks.warren.agent.RoutePeer
import java.io.IOException

// Run on the session's serial dispatcher. A directory denial fails this scope
// so even a config poll suspended in I/O is cancelled before the tunnel retries.
internal suspend fun withLiveRoutes(
    wifi: Boolean,
    proven: () -> Set<String>,
    publish: (VpnStatus) -> Unit,
    disableForwarding: () -> Unit,
    poll: suspend LiveRoutes.() -> Unit,
) = coroutineScope {
    val publication = RoutePublication(wifi, proven, publish)
    val routes = LiveRoutes(this, publication, publish, disableForwarding)
    val ticker = launch {
        while (true) {
            publication.tick()
            delay(500)
        }
    }
    try {
        routes.poll()
    } finally {
        routes.clear()
        ticker.cancel()
    }
}

internal class LiveRoutes(
    private val scope: CoroutineScope,
    private val publication: RoutePublication,
    private val publish: (VpnStatus) -> Unit,
    private val disableForwarding: () -> Unit,
) {
    private var routesJob: Job? = null
    private var routeSource: Pair<String, Endpoint>? = null
    private var routePeers: List<RoutePeer>? = null
    private var latest: Pair<AgentConfig, List<Peer>>? = null
    val ready get() = publication.ready

    fun clear() {
        routesJob?.cancel()
        routesJob = null
        discardRoutes()
    }

    fun revoke() {
        // This also invalidates the native LAN lease. Do it before the scope
        // unwinds and joins its children, then let the denial propagate.
        disableForwarding()
        discardRoutes()
        publish(VpnStatus(Phase.RECOVERING, failed = true))
    }

    private fun discardRoutes() {
        routeSource = null
        routePeers = null
        latest = null
        publication.clear()
    }

    fun update(config: AgentConfig, peers: List<Peer>) {
        val page = config.routePage
        val source = page?.let { it.revision to config.control }
        val changed = source != routeSource
        if (changed) {
            clear()
            routeSource = source
            if (page?.next == null) routePeers = page?.peers
        }
        latest = config to peers
        publication.update(config, peers, routePeers)
        if (!changed || page?.next == null) return

        routesJob = scope.launch {
            while (true) {
                val result = try {
                    AgentClient.routePeers(config)
                } catch (e: IOException) {
                    ensureActive()
                    if (e is AgentException && e.failure == AgentFailure.REVOKED) {
                        revoke()
                        throw e
                    }
                    null
                }
                ensureActive()
                if (routeSource != source) return@launch
                if (result != null) {
                    routePeers = result
                    val (current, eligible) = checkNotNull(latest)
                    publication.update(current, eligible, result)
                    return@launch
                }
                delay(1000)
            }
        }
    }
}

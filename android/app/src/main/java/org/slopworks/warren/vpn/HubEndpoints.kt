package org.slopworks.warren.vpn

import org.slopworks.warren.agent.Endpoint
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

// One retry sequence for the lifetime of a single underlay.
internal class HubEndpoints(private val resolve: (String) -> Array<InetAddress>) {
    private var target: Endpoint? = null
    private var remaining = emptyList<InetAddress>().iterator()
    private var selected: Endpoint? = null

    fun select(endpoint: Endpoint): Endpoint {
        if (target != endpoint) {
            target = endpoint
            remaining = emptyList<InetAddress>().iterator()
            selected = null
        }
        selected?.let { return it }
        if (!remaining.hasNext()) {
            remaining = resolve(endpoint.host).asSequence()
                .filterNot { it.isAnyLocalAddress || it.isMulticastAddress }
                .filterNot { it is Inet6Address && it.isLinkLocalAddress && it.scopeId == 0 }
                .distinct()
                .iterator()
        }
        if (!remaining.hasNext()) throw UnknownHostException(endpoint.host)
        return Endpoint(checkNotNull(remaining.next().hostAddress), endpoint.port).also { selected = it }
    }

    fun failed() {
        selected = null
    }
}

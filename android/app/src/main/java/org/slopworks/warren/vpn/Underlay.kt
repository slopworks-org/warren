package org.slopworks.warren.vpn

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.RouteInfo
import android.os.Build
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import org.slopworks.warren.agent.Ipv4
import org.slopworks.warren.agent.Prefix
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

internal enum class Transport { WIFI, ETHERNET, OTHER }

internal interface UnderlayRoute {
    val destination: InetAddress
    val prefixLength: Int
    val unicast: Boolean
}

// Keep RouteInfo equality, including fields such as route MTU that are not public.
private data class AndroidUnderlayRoute(val route: RouteInfo) : UnderlayRoute {
    override val destination get() = route.destination.address
    override val prefixLength get() = route.destination.prefixLength
    override val unicast get() = if (prefixLength == 0) {
        route.isDefaultRoute
    } else {
        // Older releases hide the route type. The prefix checks below still
        // keep additions from overlapping any existing IPv6 path.
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || route.type == RouteInfo.RTN_UNICAST
    }
}

internal data class UnderlayLinks(
    val interfaceName: String?,
    val addresses: Set<Pair<InetAddress, Int>>,
    val routes: Set<UnderlayRoute>,
    val mtu: Int,
) {
    fun onlyAddsIpv6To(previous: UnderlayLinks): Boolean {
        if (interfaceName != previous.interfaceName || mtu != previous.mtu) return false
        if (!addresses.containsAll(previous.addresses) || !routes.containsAll(previous.routes)) return false
        if (previous.addresses.none { it.first is Inet4Address } ||
            previous.routes.none { it.destination is Inet4Address && it.prefixLength == 0 && it.unicast }
        ) return false
        if ((addresses - previous.addresses).any { it.first !is Inet6Address }) return false
        val addedRoutes = routes - previous.routes
        if (addedRoutes.any { it.destination !is Inet6Address || !it.unicast }) return false
        if (addedRoutes.isEmpty()) return true
        val oldIpv6 = previous.routes.filter { it.destination is Inet6Address }
        // A first default extends reachability. Added non-default routes are safe
        // only during initial provisioning, while the old IPv6 paths are link-local.
        if (oldIpv6.any { it.prefixLength == 0 } || addedRoutes.count { it.prefixLength == 0 } > 1) return false
        return addedRoutes.filter { it.prefixLength != 0 }.all { route ->
            route.prefixLength >= 10 && !route.destination.isLinkLocalAddress &&
                oldIpv6.all { it.prefixLength >= 10 && it.destination.isLinkLocalAddress }
        }
    }
}

internal typealias Underlay = UnderlaySnapshot<Network>

internal data class UnderlaySnapshot<N : Any>(
    val network: N,
    val transport: Transport,
    val links: UnderlayLinks,
) {
    val wifi get() = transport == Transport.WIFI
    val lan = if (transport != Transport.OTHER) links.addresses.mapNotNull { (address, bits) ->
        if (address !is Inet4Address || bits !in 8..30) return@mapNotNull null
        val ip = Ipv4.parse(address.hostAddress ?: return@mapNotNull null)
        if (ip.isPrivate) Prefix(ip, bits) else null
    }.sortedWith(compareBy({ it.ip.bits }, { it.bits })).take(8) else emptyList()
}

internal class UnderlayTracker<N : Any>(private val publish: (UnderlaySnapshot<N>?) -> Unit) {
    private var network: N? = null
    private var transport: Transport? = null
    private var links: UnderlayLinks? = null
    private var observed: UnderlaySnapshot<N>? = null

    fun available(network: N) {
        if (this.network == network) return
        this.network = network
        transport = null
        links = null
        emit(null)
    }

    fun lost(network: N) {
        if (this.network != network) return
        this.network = null
        transport = null
        links = null
        emit(null)
    }

    fun capabilities(network: N, transport: Transport) {
        if (this.network != network) return
        this.transport = transport
        emitReady(network)
    }

    fun properties(network: N, links: UnderlayLinks) {
        if (this.network != network) return
        this.links = links
        emitReady(network)
    }

    private fun emitReady(network: N) {
        emit(UnderlaySnapshot(network, transport ?: return, links ?: return))
    }

    private fun emit(next: UnderlaySnapshot<N>?) {
        val previous = observed
        if (next == previous) return
        // Remember additions even when the sockets stay bound to the same Network.
        // Later retries can use those paths, so their removal must trigger a rebind.
        observed = next
        if (next != null && previous != null && next.wifi && previous.wifi &&
            next.network == previous.network && next.links.onlyAddsIpv6To(previous.links)
        ) return
        publish(next)
    }
}

internal fun ConnectivityManager.underlays() = callbackFlow {
    val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()
    val tracker = UnderlayTracker<Network> { trySend(it) }
    val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = tracker.available(network)

        override fun onLost(network: Network) = tracker.lost(network)

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            val transport = when {
                networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Transport.WIFI
                networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Transport.ETHERNET
                else -> Transport.OTHER
            }
            tracker.capabilities(network, transport)
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            tracker.properties(network, UnderlayLinks(
                linkProperties.interfaceName,
                linkProperties.linkAddresses.map { it.address to it.prefixLength }.toSet(),
                linkProperties.routes.map(::AndroidUnderlayRoute).toSet(),
                linkProperties.mtu,
            ))
        }
    }
    registerBestMatchingNetworkCallback(request, callback, android.os.Handler(android.os.Looper.getMainLooper()))
    awaitClose { unregisterNetworkCallback(callback) }
}.buffer(Channel.CONFLATED)

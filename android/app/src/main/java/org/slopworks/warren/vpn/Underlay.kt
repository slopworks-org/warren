package org.slopworks.warren.vpn

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.RouteInfo
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import org.slopworks.warren.agent.Ipv4
import org.slopworks.warren.agent.Prefix
import java.net.Inet4Address
import java.net.InetAddress

internal enum class Transport { WIFI, ETHERNET, OTHER }

internal data class UnderlayLinks(
    val interfaceName: String?,
    val addresses: Set<Pair<InetAddress, Int>>,
    val routes: Set<RouteInfo>,
    val mtu: Int,
)

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
    private var published: UnderlaySnapshot<N>? = null

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
        if (next == published) return
        published = next
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
                linkProperties.routes.toSet(),
                linkProperties.mtu,
            ))
        }
    }
    registerBestMatchingNetworkCallback(request, callback, android.os.Handler(android.os.Looper.getMainLooper()))
    awaitClose { unregisterNetworkCallback(callback) }
}.buffer(Channel.CONFLATED)

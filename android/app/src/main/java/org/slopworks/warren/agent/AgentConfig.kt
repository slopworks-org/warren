package org.slopworks.warren.agent

import java.net.InetAddress
import java.util.Base64

internal data class Ipv4(val bits: Int) {
    override fun toString() = (24 downTo 0 step 8).joinToString(".") { ((bits ushr it) and 255).toString() }
    fun inet() = InetAddress.getByAddress(ByteArray(4) { (bits ushr (24 - it * 8)).toByte() })
    fun probeAddress() = "fd77:6172:7265:6e00::${(bits ushr 16).toString(16)}:${(bits and 65535).toString(16)}"

    val isPrivate: Boolean
        get() = bits ushr 24 == 10 || bits ushr 20 == 0xac1 || bits ushr 16 == 0xc0a8

    companion object {
        fun parse(text: String): Ipv4 {
            val parts = text.split('.')
            require(parts.size == 4)
            return Ipv4(parts.fold(0) { result, octet ->
                require(octet.isNotEmpty() && octet.length <= 3 && octet.all { it in '0'..'9' })
                val value = octet.toInt()
                require(value <= 255)
                (result shl 8) or value
            })
        }
    }
}

internal data class Prefix(val ip: Ipv4, val bits: Int) {
    init { require(bits in 1..32) }
    fun contains(other: Ipv4) = ip.bits ushr (32 - bits) == other.bits ushr (32 - bits)
    override fun toString() = "$ip/$bits"

    companion object {
        fun parse(text: String) = Prefix(Ipv4.parse(text.substringBefore('/')), text.substringAfter('/').toInt())
    }
}

internal data class Endpoint(val host: String, val port: Int) {
    override fun toString(): String = if (':' in host) "[$host]:$port" else "$host:$port"

    companion object {
        fun parse(text: String): Endpoint {
            val host = text.substringBeforeLast(':').removeSurrounding("[", "]")
            val port = text.substringAfterLast(':').toInt()
            require(host.isNotEmpty() && host.all { it.isLetterOrDigit() || it in ".:-_" } && port in 1..65535)
            return Endpoint(host, port)
        }
    }
}

internal data class Peer(val key: String, val endpoint: Endpoint, val allowed: List<Prefix>, val keepalive: Int) {
    companion object {
        fun parse(text: String): Peer {
            val (key, endpoint, allowed, keepalive) = text.split(' ').also { require(it.size == 4) }
            val decoded = Base64.getDecoder().decode(key)
            require(decoded.size == 32 && decoded.any { it != 0.toByte() })
            return Peer(decoded.hex(), Endpoint.parse(endpoint), allowed.split(',').map(Prefix::parse),
                keepalive.toInt().also { require(it in 0..65535) })
        }
    }
}

internal data class RoutePeer(val id: String, val address: Ipv4, val name: String?) {
    companion object {
        private val idPattern = Regex("[0-9a-f]{32}")

        fun parse(text: String): RoutePeer {
            val parts = text.split(' ', limit = 3)
            require(parts.size >= 2 && idPattern.matches(parts[0]))
            val name = parts.getOrNull(2)?.trim()?.takeIf { it.isNotEmpty() }
            require(name == null || (name.codePointCount(0, name.length) <= 64 && name.none(Char::isISOControl)))
            return RoutePeer(parts[0], Ipv4.parse(parts[1]), name)
        }
    }
}

internal class AgentConfig(
    val wire: String,
    val version: ULong,
    val deviceId: ULong,
    val name: String,
    val address: Prefix,
    val control: Endpoint,
    val hub: Peer,
    val lan: List<Peer>,
    val routePeers: List<RoutePeer>?,
    val routePage: RoutePage?,
) {
    val isBootstrap get() = version == BOOTSTRAP_VERSION

    // A legacy server can omit rows at its count or byte limit. At most
    // 317 bytes per row plus 19 version digits were reserved on that server.
    val legacyRoutesMayBeTruncated = routePeers != null &&
        (routePeers.size == ROUTE_PAGE_ROWS || wire.toByteArray(Charsets.UTF_8).size > MAX_RESPONSE - 317 - 19)

    companion object {
        // Warren's config versions are 63-bit hashes. A saved bootstrap must
        // force a fresh config response even when the server has not changed.
        private val BOOTSTRAP_VERSION = ULong.MAX_VALUE

        fun bootstrapWire(wire: String): String {
            val fields = Pairs.parse(wire)
            return Pairs.of(
                "version" to BOOTSTRAP_VERSION.toString(),
                "device_id" to fields.one("device_id"),
                "name" to fields.one("name"),
                "address" to fields.one("address"),
                "control" to fields.one("control"),
                "peer" to fields.one("peer"),
            ).encode()
        }

        fun parse(fields: Pairs): AgentConfig {
            val address = Prefix.parse(fields.one("address"))
            val control = Endpoint.parse(fields.one("control"))
            val controlIp = Ipv4.parse(control.host)
            val hub = Peer.parse(fields.one("peer"))
            require(controlIp != address.ip && hub.allowed.any { it.contains(controlIp) })
            require(hub.allowed.any { it.contains(address.ip) })
            val lan = fields.all("lan_peer_v2").map(Peer::parse)
            val addresses = lan.map { peer ->
                val route = peer.allowed.single()
                require(peer.key != hub.key && route.bits == 32 && route.ip != address.ip && route.ip != controlIp)
                require(hub.allowed.any { it.contains(route.ip) } && Ipv4.parse(peer.endpoint.host).isPrivate)
                route.ip
            }
            require(addresses.distinct().size == lan.size && lan.map(Peer::key).distinct().size == lan.size)
            val marker = fields.all("route_peers")
            require(marker in listOf(emptyList(), listOf("1"), listOf("2")))
            val targets = RouteTargets(address.ip, controlIp, hub.allowed)
            val routePeers = if (marker == listOf("1")) targets.parse(fields) else null
            val routePage = if (marker == listOf("2")) RoutePage.parse(fields, targets) else null
            require(marker.isNotEmpty() || fields.all("route_peer").isEmpty())
            return AgentConfig(fields.encode("mac"), fields.one("version").toULong(),
                fields.one("device_id").toULong(), fields.one("name"), address, control, hub, lan, routePeers, routePage)
        }
    }
}

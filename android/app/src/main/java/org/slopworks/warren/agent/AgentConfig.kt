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

internal class AgentConfig(
    val wire: String,
    val version: ULong,
    val deviceId: ULong,
    val name: String,
    val address: Prefix,
    val control: Endpoint,
    val hub: Peer,
    val lan: List<Peer>,
) {
    companion object {
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
            return AgentConfig(fields.encode("mac"), fields.one("version").toULong(),
                fields.one("device_id").toULong(), fields.one("name"), address, control, hub, lan)
        }
    }
}

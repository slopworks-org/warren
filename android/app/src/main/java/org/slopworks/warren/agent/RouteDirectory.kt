package org.slopworks.warren.agent

internal const val ROUTE_PAGE_ROWS = 256

internal class RouteTargets(private val source: Ipv4, private val control: Ipv4, private val allowed: List<Prefix>) {
    fun parse(fields: Pairs): List<RoutePeer> {
        val rows = fields.all("route_peer")
        require(rows.size <= ROUTE_PAGE_ROWS)
        val peers = rows.map(RoutePeer::parse)
        require(peers.map(RoutePeer::id).distinct().size == peers.size)
        require(peers.map(RoutePeer::address).distinct().size == peers.size)
        require(peers.all { it.address != source && it.address != control && allowed.any { route -> route.contains(it.address) } })
        return peers
    }
}

internal data class RoutePage(val revision: String, val peers: List<RoutePeer>, val next: String?) {
    companion object {
        private val revisionPattern = Regex("[0-9a-f]{64}")

        fun parse(fields: Pairs, targets: RouteTargets): RoutePage {
            require(fields.one("route_peers") == "2")
            val revision = fields.one("route_revision").also { require(revisionPattern.matches(it)) }
            val peers = targets.parse(fields)
            require(peers.zipWithNext().all { (a, b) -> a.address.bits.toUInt() < b.address.bits.toUInt() })
            val next = requireNotNull(fields.all("route_next").singleOrNull()).takeUnless { it == "end" }
            when (next) {
                null -> Unit
                "start" -> require(peers.isEmpty())
                else -> require(peers.lastOrNull()?.address?.toString() == next)
            }
            return RoutePage(revision, peers, next)
        }
    }
}

// A conflict or revocation invalidates the entire attempt. Only return rows after the
// directory has ended on the same revision with strictly advancing addresses.
internal suspend fun AgentConfig.collectRoutePeers(request: suspend (String) -> Reply): List<RoutePeer>? {
    var page = checkNotNull(routePage)
    val revision = page.revision
    val peers = page.peers.toMutableList()
    val ids = peers.mapTo(mutableSetOf(), RoutePeer::id)
    val targets = RouteTargets(address.ip, Ipv4.parse(control.host), hub.allowed)
    while (true) {
        val next = page.next ?: return peers
        val after = if (next == "start") "" else "&after=$next"
        val reply = request("/agent/v1/routes?revision=$revision$after")
        when (reply.status) {
            200 -> page = RoutePage.parse(Pairs.parse(reply.body), targets)
            403, 409 -> return null
            else -> throw AgentException(AgentFailure.PROTOCOL)
        }
        require(page.revision == revision && page.peers.isNotEmpty())
        val first = page.peers.first().address.bits.toUInt()
        val last = peers.lastOrNull()?.address?.bits?.toUInt()
        require(last == null || first > last)
        require(page.peers.all { ids.add(it.id) })
        peers.addAll(page.peers)
    }
}

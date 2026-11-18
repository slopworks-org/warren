package org.slopworks.warren.vpn

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNotNull
import org.junit.Test
import org.slopworks.warren.agent.AgentConfig
import org.slopworks.warren.agent.AgentException
import org.slopworks.warren.agent.AgentFailure
import org.slopworks.warren.agent.Endpoint
import org.slopworks.warren.agent.Pairs
import org.slopworks.warren.agent.Peer
import org.slopworks.warren.agent.Prefix
import org.slopworks.warren.agent.Reply
import org.slopworks.warren.agent.RoutePeer
import org.slopworks.warren.agent.collectRoutePeers
import java.io.File

class RouteDirectoryTest {
    @Test
    fun loadsInlineEmptyAndSeparateFirstPages() = runBlocking {
        val empty = config(page("end"))
        assertEquals(emptyList<Any>(), empty.collectRoutePeers { error("empty directory required a request") })
        val small = config(page("end", row(4)))
        assertEquals(listOf("peer-4"), small.collectRoutePeers { error("inline directory required a request") }?.map { it.name })
        val noSpace = config(page("start"))
        val collected = noSpace.collectRoutePeers { path ->
            assertEquals("/agent/v1/routes?revision=$revision", path)
            Reply(200, page("end", row(4)))
        }
        assertEquals(listOf("peer-4"), collected?.map { it.name })
        val header = Reply(200, base.substringAfter('\n'), "42 $revision start").config()
        assertEquals(42uL, header.version)
        assertEquals(noSpace.routePage, header.routePage)
    }

    @Test
    fun rejectsStalledCursorsMixedRevisionsAndFalseEnds() {
        val first = config(page("10.77.0.4", row(4)))
        val invalid = listOf(
            page("10.77.0.4", row(4)),
            page("end", row(5)).replace(revision, "b".repeat(64)),
            page("end"),
            page("end", row(5)).replace("route_next=end\n", ""),
            page("end", row(6) + row(5)),
            page("end", row(5).replace(id(5), id(4))),
        )
        for (body in invalid) {
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { first.collectRoutePeers { Reply(200, body) } }
            }
        }
        assertNull(runBlocking { first.collectRoutePeers { Reply(409, "") } })
        val denied = assertThrows(AgentException::class.java) {
            runBlocking { first.collectRoutePeers { Reply(403, "") } }
        }
        assertEquals(AgentFailure.REVOKED, denied.failure)
    }

    @Test
    fun detectsLegacyCountAndByteLimits() {
        val legacy = "route_peers=1\n"
        assertFalse(config(legacy + row(4)).legacyRoutesMayBeTruncated)
        val full = config(legacy + (4..259).joinToString("") { row(it) })
        assertTrue(full.legacyRoutesMayBeTruncated)
        val almostFull = "256".repeat(87_300)
        val byteLimited = config(legacy + row(4), base.replace("name=Android", "name=$almostFull"))
        assertTrue(byteLimited.legacyRoutesMayBeTruncated)
    }

    @Test
    fun truncatedLegacyUpdateCannotRepublishRevokedPeerOnNextTick() {
        val legacy = "route_peers=1\n"
        val initial = config(legacy + (4..258).joinToString("") { row(it) })
        val truncated = config(legacy + (5..260).joinToString("") { row(it) })
        val updates = mutableListOf<VpnStatus>()
        val publication = RoutePublication(wifi = true, proven = { setOf(address(4)) }, publish = { updates.add(it) })
        publication.update(initial, emptyList(), null)
        assertNull(initial.routePage)
        assertEquals(id(4), updates.last().peers?.single { it.name == "peer-4" }?.id)

        assertNull(truncated.routePage)
        publication.update(truncated, emptyList(), null)
        assertEquals(VpnStatus(Phase.CONNECTED), updates.last())
        publication.tick()
        assertEquals(2, updates.size)
        assertNull(updates.last().peers)
    }

    @Test
    fun consumesMixedAclPagesFromTheServer() = runBlocking {
        // Generate with WARREN_ROUTE_TEST_TRANSCRIPT=<file> cargo test -p warren-server --test agent_routes.
        val file = System.getenv("WARREN_ROUTE_TEST_TRANSCRIPT")
        assumeNotNull(file)
        val exchanges = File(requireNotNull(file)).readText().split('\u0000').filter(String::isNotEmpty).map { entry ->
            val (status, path, body) = entry.split('\n', limit = 3)
            path to Reply(status.toInt(), body)
        }.iterator()
        fun request(path: String): Reply {
            val (actual, response) = exchanges.next()
            assertEquals(actual, path)
            return response
        }
        fun poll() = request("/agent/v1/config?route_peers=1&route_pages=true").also { assertEquals(200, it.status) }.config()
        fun paths(config: AgentConfig, directory: List<RoutePeer>): List<PeerPath> {
            val direct = Peer("test-key", Endpoint.parse("192.168.0.8:51820"), listOf(Prefix.parse("10.77.1.12/32")), 15)
            return PeerRoutes(config, listOf(direct), directory).paths(setOf("10.77.1.12"), wifi = true)
        }

        val initial = poll()
        val all = paths(initial, checkNotNull(initial.collectRoutePeers(::request)))
        assertEquals((3..269).map(::address), all.map(PeerPath::address))
        assertTrue(all.single { it.address == address(267) }.let { it.name?.startsWith("peer-267 ") == true && !it.direct })
        assertEquals(address(268), all.single(PeerPath::direct).address)

        assertNull(initial.collectRoutePeers(::request))
        val refreshed = poll()
        val current = paths(refreshed, checkNotNull(refreshed.collectRoutePeers(::request)))
        assertEquals((4..268).map(::address), current.map(PeerPath::address))
        assertEquals(address(268), current.single(PeerPath::direct).address)
        assertTrue(poll().collectRoutePeers(::request)?.isEmpty() == true)
        assertFalse(exchanges.hasNext())
    }

    private fun config(extra: String, prefix: String = base) = AgentConfig.parse(Pairs.parse(prefix + extra))
    private fun page(next: String, rows: String = "") = "route_peers=2\nroute_revision=$revision\nroute_next=$next\n$rows"
    private fun id(host: Int) = host.toString(16).padStart(32, '0')
    private fun address(host: Int) = "10.77.${host / 256}.${host % 256}"
    private fun row(host: Int) = "route_peer=${id(host)} ${address(host)} peer-$host\n"

    private companion object {
        val revision = "a".repeat(64)
        const val base = "version=42\ndevice_id=3\nname=Android\naddress=10.77.0.3/16\ncontrol=10.77.0.1:7180\n" +
            "peer=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc= hub.example:51820 10.77.0.0/16 25\n"
    }
}

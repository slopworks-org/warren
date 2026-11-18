package org.slopworks.warren.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.slopworks.warren.agent.AgentClient
import org.slopworks.warren.agent.AgentConfig
import org.slopworks.warren.agent.AgentException
import org.slopworks.warren.agent.AgentFailure
import org.slopworks.warren.agent.Endpoint
import org.slopworks.warren.agent.Ipv4
import org.slopworks.warren.agent.Peer
import org.slopworks.warren.agent.Prefix
import org.slopworks.warren.agent.Profile
import org.slopworks.warren.agent.RoutePage
import org.slopworks.warren.agent.RoutePeer
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket

class LiveRoutesTest {
    @Test
    fun directoryDenialRetiresPendingPollBeforeBackoffAndPreservesIntentUntilStop() = runBlocking {
        listener().use { server ->
            val profile = Profile("https://hub.example", "f".repeat(64), config(server, revision, next = null))
            val staleStarted = Channel<Unit>()
            val replies = async(Dispatchers.IO) {
                repeat(2) {
                    server.accept().use { socket ->
                        assertTrue(socket.request().startsWith("/agent/v1/config?v=42&wait=0&"))
                        socket.respond("304 Not Modified")
                    }
                    server.accept().use { stale ->
                        assertEquals(path(staleRevision), stale.request())
                        staleStarted.send(Unit)
                        server.accept().use { first ->
                            server.accept().use { second ->
                                val requests = listOf(first, second).associateBy { it.request() }
                                val pending = requests.entries.single { it.key.startsWith("/agent/v1/config?v=42&wait=50&") }.value
                                requests.getValue(path(revision)).respond("403 Forbidden")
                                // The pending poll receives no response. Retirement closes its socket.
                                assertEquals(-1, pending.getInputStream().read())
                                assertEquals(-1, stale.getInputStream().read())
                                runCatching { stale.respond("200 OK", pageBody(staleRevision, "obsolete")) }
                            }
                        }
                    }
                }
            }
            var desired = true
            var forwarding = false
            var lanAuthorized = false
            val statuses = mutableListOf<VpnStatus>()
            val waits = mutableListOf<Long>()
            val usedProfiles = mutableListOf<Profile>()
            var retired = 0
            val backoffStarted = CompletableDeferred<Unit>()
            val recovery = VpnStatus(Phase.RECOVERING, failed = true)
            val worker = launch {
                retryTunnel(
                    desired = { desired },
                    attempt = {
                        usedProfiles.add(profile)
                        try {
                            withLiveRoutes(true, { setOf("127.0.0.3") }, statuses::add, disableForwarding = {
                                forwarding = false
                                lanAuthorized = false
                            }) {
                                val current = profile.config
                                assertNull(AgentClient.poll(current, 0, emptyList(), 0, onForbidden = ::revoke))
                                forwarding = true
                                lanAuthorized = true
                                update(current, listOf(lanPeer))
                                assertTrue(statuses.last().peers!!.single().direct)
                                update(config(server, staleRevision), listOf(lanPeer))
                                staleStarted.receive()
                                update(config(server, revision), listOf(lanPeer))
                                try {
                                    AgentClient.poll(current, 50, emptyList(), 0, onForbidden = ::revoke)
                                    throw AssertionError("a pending poll survived directory denial")
                                } finally {
                                    assertFalse(forwarding)
                                    assertFalse(lanAuthorized)
                                    assertFalse(ready)
                                    assertEquals(recovery, statuses.last())
                                }
                            }
                        } catch (e: AgentException) {
                            assertEquals(AgentFailure.REVOKED, e.failure)
                            retired++
                            throw e
                        }
                    },
                    canRetry = { true },
                    wait = {
                        waits.add(it)
                        assertEquals(waits.size, retired)
                        assertTrue(desired)
                        assertEquals(recovery, statuses.last())
                        if (waits.size == 2) {
                            backoffStarted.complete(Unit)
                            awaitCancellation()
                        }
                    },
                )
            }
            withTimeout(12_000) { backoffStarted.await() }
            desired = false
            worker.cancelAndJoin()
            replies.await()
            assertEquals(listOf(1000L, 2000L), waits)
            assertEquals(2, usedProfiles.size)
            usedProfiles.forEach { assertSame(profile, it) }
            assertEquals(2, statuses.count { it == recovery })
            assertEquals(recovery, statuses.last())
            assertTrue(statuses.flatMap { it.peers.orEmpty() }.none { it.name == "obsolete" })
        }
    }

    @Test
    fun directoryConflictRetriesWithoutWithdrawingHealthyForwarding() = runBlocking {
        listener().use { server ->
            val current = config(server, revision)
            val replies = async(Dispatchers.IO) {
                for ((expected, status, body) in listOf(
                    Triple("/agent/v1/config?v=42&wait=0&", "304 Not Modified", ""),
                    Triple(path(revision), "409 Conflict", ""),
                    Triple(path(revision), "200 OK", pageBody(revision, "fresh")),
                    Triple("/agent/v1/config?v=42&wait=0&", "304 Not Modified", ""),
                )) {
                    server.accept().use { socket ->
                        assertTrue(socket.request().startsWith(expected))
                        socket.respond(status, body)
                    }
                }
            }
            val statuses = mutableListOf<VpnStatus>()
            val loaded = CompletableDeferred<Unit>()
            withLiveRoutes(true, { setOf("127.0.0.3") }, publish = {
                statuses.add(it)
                if (it.peers != null) loaded.complete(Unit)
            }, disableForwarding = { throw AssertionError("conflict withdrew forwarding") }) {
                assertNull(AgentClient.poll(current, 0, emptyList(), 0, onForbidden = ::revoke))
                update(current, listOf(lanPeer))
                withTimeout(5000) { loaded.await() }
                assertNull(AgentClient.poll(current, 0, emptyList(), 0, onForbidden = ::revoke))
                assertTrue(ready)
            }
            replies.await()
            assertEquals(VpnStatus(Phase.CONNECTED, routesLoading = true), statuses.first())
            assertTrue(statuses.all { it.phase == Phase.CONNECTED })
            assertEquals(listOf("cached", "fresh"), statuses.last().peers!!.map(PeerPath::name))
            assertTrue(statuses.last().peers!!.first().direct)
        }
    }

    private fun listener() = ServerSocket(0, 4, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 5000 }

    private fun Socket.request(): String {
        soTimeout = 5000
        assertEquals("127.0.0.1", inetAddress.hostAddress)
        val input = getInputStream().bufferedReader()
        val first = input.readLine()
        while (!input.readLine().isNullOrEmpty()) { /* Consume request headers. */ }
        return first.split(' ')[1]
    }

    private fun Socket.respond(status: String, body: String = "") {
        getOutputStream().write("HTTP/1.0 $status\r\nContent-Length: ${body.length}\r\n\r\n$body".toByteArray())
    }

    private fun config(server: ServerSocket, revision: String, next: String? = "127.0.0.3") = AgentConfig(
        wire = "", version = 42u, deviceId = 7u, name = "Android",
        address = Prefix.parse("127.0.0.1/8"), control = Endpoint("127.0.0.1", server.localPort),
        hub = Peer("hub-key", Endpoint("hub.example", 51820), listOf(Prefix.parse("127.0.0.0/8")), 25),
        lan = listOf(lanPeer), routePeers = null,
        routePage = RoutePage(revision, listOf(RoutePeer("1".repeat(32), Ipv4.parse("127.0.0.3"), "cached")), next),
    )

    private fun path(revision: String) = "/agent/v1/routes?revision=$revision&after=127.0.0.3"

    private fun pageBody(revision: String, name: String) =
        "route_peers=2\nroute_revision=$revision\nroute_next=end\nroute_peer=${"2".repeat(32)} 127.0.0.4 $name\n"

    private companion object {
        val revision = "a".repeat(64)
        val staleRevision = "b".repeat(64)
        val lanPeer = Peer("lan-key", Endpoint("192.168.1.3", 51820), listOf(Prefix.parse("127.0.0.3/32")), 25)
    }
}

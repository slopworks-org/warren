package org.slopworks.warren.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.slopworks.warren.agent.AgentClient
import org.slopworks.warren.agent.AgentConfig
import org.slopworks.warren.agent.AgentException
import org.slopworks.warren.agent.AgentFailure
import org.slopworks.warren.agent.Pairs
import org.slopworks.warren.agent.ProfileStore
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

class ProfileDirectoryPersistenceTest {
    @get:Rule val folder = TemporaryFolder()

    @Test
    fun directoryDenialReloadsBootstrapAndFetchesFreshRows() = verifyDenial(directory = true)

    @Test
    fun configDenialReloadsBootstrapAndFetchesFreshRows() = verifyDenial(directory = false)

    private fun verifyDenial(directory: Boolean) = runBlocking {
        ServerSocket(0, 4, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 5000
            val file = folder.newFile("agent")
            val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
            fun store() = ProfileStore(file::readBytes, file::writeBytes, { key }, { false })
            val oldConfig = config(server.localPort, 42, oldRevision, "Old private device")
            val legacy = JSONObject().put("server", "https://hub.example").put("key", "a".repeat(64))
                .put("connected", true).put("config", oldConfig)
                .put("pending", JSONObject().put("server", "https://next.example").put("key", "b".repeat(64))
                    .put("token", Base64.getEncoder().encodeToString(ByteArray(24)))
                    .put("nonce", "pending-nonce").put("request", "pending-request"))
            val encrypt = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
            file.writeBytes(encrypt.iv + encrypt.doFinal(legacy.toString().toByteArray()))

            val initial = checkNotNull(store().activeProfile())
            assertTrue(initial.config.isBootstrap)
            var stale = initial
            val statuses = mutableListOf<VpnStatus>()
            val replies = async(Dispatchers.IO) {
                server.reply(bootstrapPoll, "200 OK", oldConfig)
                val deniedPath = if (directory) continuation(oldRevision) else "/agent/v1/config?v=42&"
                server.reply(deniedPath, "403 Forbidden")
                server.reply(bootstrapPoll, "304 Not Modified")
                server.reply(bootstrapPoll, "200 OK", config(server.localPort, 43, nextRevision, "Fresh private device"))
                server.reply(continuation(nextRevision), "200 OK",
                    "route_peers=2\nroute_revision=$nextRevision\nroute_next=end\n" +
                        "route_peer=${"2".repeat(32)} 127.0.0.4 Fresh continuation\n")
                server.reply("/agent/v1/config?v=43&", "304 Not Modified")
            }

            try {
                withLiveRoutes(false, { emptySet() }, statuses::add, disableForwarding = {}) {
                    val current = checkNotNull(AgentClient.poll(initial.config.onHostLoopback(), 0, emptyList(), 0, onForbidden = ::revoke))
                    stale = initial.withConfig(current)
                    store().saveConfig(stale)
                    if (directory) {
                        update(current.onHostLoopback(), emptyList())
                        withTimeout(5000) { awaitCancellation() }
                    } else {
                        AgentClient.poll(current.onHostLoopback(), 0, emptyList(), 0, onForbidden = ::revoke)
                    }
                }
                fail("A 403 must retire the live directory")
            } catch (e: AgentException) {
                assertEquals(AgentFailure.REVOKED, e.failure)
            }

            // A late save, an off-state read, and a process-style reload all use
            // the same encrypted bytes and cannot restore the denied directory.
            val lateSave = async(Dispatchers.IO) { store().saveConfig(stale) }
            val retry = checkNotNull(store().activeProfile())
            lateSave.await()
            assertEquals(initial.privateKey, retry.privateKey)
            assertEquals(initial.server, retry.server)
            assertEquals(initial.config.deviceId, retry.config.deviceId)
            assertEquals(initial.config.hub, retry.config.hub)
            assertEquals(initial.config.control, retry.config.control)
            assertTrue(store().wantsVpn)
            assertEquals("pending-request", store().pendingEnrollment().request.body)
            assertTrue(retry.config.isBootstrap)
            assertNull(retry.config.routePage)
            assertNull(retry.config.routePeers)

            val loaded = CompletableDeferred<List<PeerPath>>()
            withLiveRoutes(false, { emptySet() }, publish = {
                statuses.add(it)
                it.peers?.let(loaded::complete)
            }, disableForwarding = { fail("Fresh config denied") }) {
                val bootstrap = retry.config.onHostLoopback()
                assertNull(AgentClient.poll(bootstrap, 0, emptyList(), 0, onForbidden = ::revoke))
                assertFalse(ready)
                val fresh = checkNotNull(AgentClient.poll(bootstrap, 0, emptyList(), 0, onForbidden = ::revoke))
                store().saveConfig(retry.withConfig(fresh))
                update(fresh.onHostLoopback(), emptyList())
                assertEquals(listOf("Fresh private device", "Fresh continuation"),
                    withTimeout(5000) { loaded.await() }.map(PeerPath::name))
                assertNull(AgentClient.poll(fresh.onHostLoopback(), 0, emptyList(), 0, onForbidden = ::revoke))
            }
            replies.await()
            assertTrue(statuses.flatMap { it.peers.orEmpty() }.none { it.name == "Old private device" })

            store().wantsVpn = false
            val oldOtherControl = config(server.localPort + if (server.localPort == 65535) -1 else 1, 42, oldRevision, "Old private device")
            store().saveConfig(stale.withConfig(AgentConfig.parse(Pairs.parse(oldOtherControl))))
            assertFalse(store().wantsVpn)
            assertNull(store().activeProfile())
            assertEquals(initial.config.control, store().load()?.config?.control)
            val bytes = file.readBytes()
            val decrypted = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
                doFinal(bytes, 12, bytes.size - 12).decodeToString()
            }
            assertFalse(decrypted.contains("private device"))
            val wire = JSONObject(decrypted).getString("config")
            assertEquals(initial.config.wire, wire)
            assertFalse(wire.contains("route_"))
        }
    }

    private fun ServerSocket.reply(path: String, status: String, body: String = "") {
        accept().use { socket ->
            assertTrue(socket.request().startsWith(path))
            socket.getOutputStream().write("HTTP/1.0 $status\r\nContent-Length: ${body.length}\r\n\r\n$body".toByteArray())
        }
    }

    private fun Socket.request(): String {
        soTimeout = 5000
        val input = getInputStream().bufferedReader()
        val first = input.readLine()
        while (!input.readLine().isNullOrEmpty()) { /* Consume request headers. */ }
        return first.split(' ')[1]
    }

    private fun config(port: Int, version: Int, revision: String, name: String) =
        "version=$version\ndevice_id=7\nname=Android\naddress=127.0.0.1/8\n" +
            "control=127.0.0.2:$port\npeer=$hubKey hub.example:51820 127.0.0.0/8 25\n" +
            "route_peers=2\nroute_revision=$revision\nroute_next=127.0.0.3\n" +
            "route_peer=${"1".repeat(32)} 127.0.0.3 $name\n"

    private fun continuation(revision: String) = "/agent/v1/routes?revision=$revision&after=127.0.0.3"

    // The two VPN addresses are distinct in the persisted wire config. The
    // host's loopback socket stands in for the TUN for HTTP exchanges only.
    private fun AgentConfig.onHostLoopback() = AgentConfig(
        wire, version, deviceId, name, address, control.copy(host = address.ip.toString()),
        hub, lan, routePeers, routePage,
    )

    private companion object {
        val bootstrapPoll = "/agent/v1/config?v=${ULong.MAX_VALUE}&wait=0&"
        val oldRevision = "a".repeat(64)
        val nextRevision = "b".repeat(64)
        val hubKey = Base64.getEncoder().encodeToString(ByteArray(32) { 1 })
    }
}

package org.slopworks.warren.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.slopworks.warren.agent.AgentClient
import org.slopworks.warren.agent.AgentConfig
import org.slopworks.warren.agent.AgentException
import org.slopworks.warren.agent.AgentFailure
import org.slopworks.warren.agent.Endpoint
import org.slopworks.warren.agent.Peer
import org.slopworks.warren.agent.Prefix
import org.slopworks.warren.agent.Profile
import java.net.InetAddress
import java.net.ServerSocket

class TunnelRetryTest {
    @Test
    fun forbiddenPollWithdrawsAndRetriesSameProfileUntilAuthorizedOrDisconnected() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        ServerSocket(0, 1, loopback).use { server ->
            server.soTimeout = 5000
            // Both ends use the host loopback interface instead of a VPN TUN.
            val config = AgentConfig(
                wire = "", version = 42u, deviceId = 7u, name = "Android",
                address = Prefix.parse("127.0.0.1/8"), control = Endpoint("127.0.0.1", server.localPort),
                hub = Peer("hub-key", Endpoint("hub.example", 51820), listOf(Prefix.parse("127.0.0.0/8")), 25),
                lan = emptyList(), routePeers = null, routePage = null,
            )
            val profile = Profile("https://hub.example", "a".repeat(64), config)
            val replies = async(Dispatchers.IO) {
                listOf("403 Forbidden", "403 Forbidden", "304 Not Modified", "403 Forbidden").map { status ->
                    server.accept().use { socket ->
                        socket.soTimeout = 5000
                        val request = socket.getInputStream().bufferedReader()
                        val first = request.readLine()
                        while (!request.readLine().isNullOrEmpty()) { /* Consume request headers. */ }
                        socket.getOutputStream().write("HTTP/1.0 $status\r\nContent-Length: 0\r\n\r\n".toByteArray())
                        socket.inetAddress.hostAddress to first
                    }
                }
            }
            var desired = true
            var forwarding = true
            var withdrawn = 0
            val usedProfiles = mutableListOf<Profile>()
            val waits = mutableListOf<Long>()
            retryTunnel(
                desired = { desired },
                attempt = {
                    usedProfiles.add(profile)
                    try {
                        AgentClient.poll(profile.config, 0, emptyList(), 0) {
                            forwarding = false
                            withdrawn++
                        }
                    } catch (e: Exception) {
                        if (e !is AgentException || e.failure != AgentFailure.REVOKED) throw AssertionError(e)
                        throw e
                    }
                    forwarding = true
                },
                canRetry = {
                    assertFalse(forwarding)
                    assertTrue(desired)
                    true
                },
                wait = {
                    waits.add(it)
                    assertEquals(waits.size == 3, forwarding)
                    if (waits.size == 4) desired = false
                },
            )
            assertEquals(3, withdrawn)
            assertEquals(listOf(1000L, 2000L, 1000L, 1000L), waits)
            assertEquals(4, usedProfiles.size)
            usedProfiles.forEach { assertSame(profile, it) }
            val (source, request) = replies.await().distinct().single()
            assertEquals("127.0.0.1", source)
            assertTrue(request.startsWith("GET /agent/v1/config?v=42&"))
        }
    }
}

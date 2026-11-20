package org.slopworks.warren.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.slopworks.warren.agent.Endpoint
import java.net.InetAddress
import java.net.UnknownHostException

class HubEndpointsTest {
    private val hub = Endpoint("warren.example", 51820)
    private val ipv4a = InetAddress.getByName("192.0.2.1")
    private val ipv4b = InetAddress.getByName("192.0.2.2")
    private val ipv6 = InetAddress.getByName("2001:db8::1")

    @Test
    fun failedEstablishmentTriesEveryAddressBeforeResolvingAgain() {
        var lookups = 0
        val candidates = HubEndpoints { host ->
            assertEquals(hub.host, host)
            if (++lookups == 1) arrayOf(ipv4a, ipv4a, ipv6, ipv4b) else arrayOf(ipv6)
        }
        assertEquals(ipv4a.hostAddress, candidates.select(hub).host)

        candidates.failed()
        assertEquals("[${ipv6.hostAddress}]:51820", candidates.select(hub).toString())
        assertEquals(ipv6.hostAddress, candidates.select(hub).host)
        assertEquals(1, lookups)

        candidates.failed()
        assertEquals(ipv4b.hostAddress, candidates.select(hub).host)
        assertEquals(1, lookups)
        candidates.failed()
        assertEquals(ipv6.hostAddress, candidates.select(hub).host)
        assertEquals(2, lookups)
    }

    @Test
    fun underlayAndConfiguredEndpointChangesStartNewSequences() {
        val wifi = HubEndpoints { arrayOf(ipv4a, ipv4b) }
        val cellular = HubEndpoints { arrayOf(ipv6) }
        wifi.select(hub)
        wifi.failed()
        assertEquals(ipv4b.hostAddress, wifi.select(hub).host)
        assertEquals(ipv6.hostAddress, cellular.select(hub).host)
        assertEquals(Endpoint(checkNotNull(ipv4a.hostAddress), 51821), wifi.select(hub.copy(port = 51821)))
    }

    @Test
    fun unusableAnswersAreSkippedAndAnEmptyLookupCanBeRetried() {
        val invalid = arrayOf(
            InetAddress.getByName("0.0.0.0"),
            InetAddress.getByName("ff02::1"),
            InetAddress.getByName("fe80::1"),
        )
        var lookups = 0
        val candidates = HubEndpoints { if (++lookups == 1) invalid else invalid + ipv6 }
        assertThrows(UnknownHostException::class.java) { candidates.select(hub) }
        assertEquals(ipv6.hostAddress, candidates.select(hub).host)
    }
}

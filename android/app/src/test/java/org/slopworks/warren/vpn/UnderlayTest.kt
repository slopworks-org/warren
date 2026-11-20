package org.slopworks.warren.vpn

import org.junit.Assert.assertEquals
import org.junit.Test
import org.slopworks.warren.agent.Endpoint
import org.slopworks.warren.agent.Prefix
import java.net.InetAddress

class UnderlayTest {
    private val ipv4 = InetAddress.getByName("192.168.1.7") to 24
    private val ipv6 = InetAddress.getByName("2001:db8::1") to 64
    private val links = UnderlayLinks("wlan0", setOf(ipv4, ipv6), emptySet(), 1500)

    private val wifiV4 = route("0.0.0.0", 0, "10.0.2.2")
    private val wifiV6 = route("::", 0, "fe80::2")
    private val wifi = UnderlayLinks(
        "wlan0",
        setOf(InetAddress.getByName("10.0.2.16") to 24, InetAddress.getByName("fe80::5161:8a83:6339:b377") to 64),
        setOf(wifiV4, route("10.0.2.0", 24), route("fe80::", 64)),
        0,
    )
    private val dualStack = wifi.copy(
        addresses = wifi.addresses + setOf(
            InetAddress.getByName("fec0::5b65:12f0:a261:6b86") to 64,
            InetAddress.getByName("fec0::6dd5:ce85:5529:3822") to 64,
        ),
        routes = wifi.routes + setOf(wifiV6, route("fec0::", 64)),
    )

    @Test
    fun wifiIpv6ProvisioningAfterCellularHandoverKeepsFirstWifiSession() {
        val changes = mutableListOf<UnderlaySnapshot<Int>?>()
        val tracker = UnderlayTracker<Int> { changes.add(it) }
        val cellular = links.copy(interfaceName = "rmnet0")
        tracker.available(101)
        tracker.capabilities(101, Transport.OTHER)
        tracker.properties(101, cellular)
        tracker.available(105)
        tracker.capabilities(105, Transport.WIFI)
        tracker.properties(105, wifi)
        tracker.capabilities(105, Transport.WIFI) // Validation callback.
        tracker.lost(101)
        tracker.properties(105, dualStack)
        tracker.properties(105, dualStack)

        assertEquals(listOf(
            UnderlaySnapshot(101, Transport.OTHER, cellular),
            null,
            UnderlaySnapshot(105, Transport.WIFI, wifi),
        ), changes)
        assertEquals(listOf(Prefix.parse("10.0.2.16/24")), changes.last()?.lan)
    }

    @Test
    fun removalOrReplacementAfterSuppressedAdditionStillRebinds() {
        val changedLinks = listOf(
            wifi, // All newly provisioned IPv6 paths disappear.
            dualStack.copy(addresses = dualStack.addresses - (InetAddress.getByName("fec0::5b65:12f0:a261:6b86") to 64)),
            dualStack.copy(addresses = dualStack.addresses.filterNot { it.first == InetAddress.getByName("10.0.2.16") }.toSet()),
            dualStack.copy(addresses = dualStack.addresses - (InetAddress.getByName("10.0.2.16") to 24) +
                (InetAddress.getByName("10.0.2.16") to 25)),
            dualStack.copy(routes = dualStack.routes - wifiV6),
            dualStack.copy(routes = dualStack.routes - wifiV4 + wifiV4.copy(gateway = "10.0.2.1")),
            dualStack.copy(routes = dualStack.routes + wifiV6.copy(gateway = "fe80::3")),
            dualStack.copy(mtu = 1400),
        )
        for (changed in changedLinks) {
            val changes = mutableListOf<UnderlaySnapshot<Int>?>()
            val tracker = UnderlayTracker<Int> { changes.add(it) }
            tracker.available(105)
            tracker.capabilities(105, Transport.WIFI)
            tracker.properties(105, wifi)
            tracker.properties(105, dualStack)
            tracker.properties(105, changed)
            assertEquals(changed.toString(), listOf(
                UnderlaySnapshot(105, Transport.WIFI, wifi),
                UnderlaySnapshot(105, Transport.WIFI, changed),
            ), changes)
        }
    }

    @Test
    fun ipv6AdditionStillPublishesWhenIpv4WasNotReadyOrTransportChanged() {
        val changes = mutableListOf<UnderlaySnapshot<Int>?>()
        val tracker = UnderlayTracker<Int> { changes.add(it) }
        val noDefault = wifi.copy(routes = wifi.routes - wifiV4)
        val ipv6Ready = dualStack.copy(routes = dualStack.routes - wifiV4)
        tracker.available(105)
        tracker.capabilities(105, Transport.WIFI)
        tracker.properties(105, noDefault)
        tracker.properties(105, ipv6Ready)
        tracker.capabilities(105, Transport.ETHERNET)
        tracker.lost(105)
        assertEquals(listOf(
            UnderlaySnapshot(105, Transport.WIFI, noDefault),
            UnderlaySnapshot(105, Transport.WIFI, ipv6Ready),
            UnderlaySnapshot(105, Transport.ETHERNET, ipv6Ready),
            null,
        ), changes)
    }

    @Test
    fun preservedSessionCanResolveNewAaaaAfterItsSavedAFails() {
        val hub = Endpoint("hub.example", 51820)
        val a = InetAddress.getByName("192.0.2.1")
        val aaaa = InetAddress.getByName("2001:db8::1")
        var answers = arrayOf(a)
        val sequences = mutableListOf<HubEndpoints>()
        val tracker = UnderlayTracker<Int> { if (it != null) sequences.add(HubEndpoints { answers }) }
        tracker.available(105)
        tracker.capabilities(105, Transport.WIFI)
        tracker.properties(105, wifi)
        val endpoints = sequences.single()
        assertEquals(a.hostAddress, endpoints.select(hub).host)

        answers = arrayOf(aaaa)
        tracker.properties(105, dualStack)
        assertEquals(1, sequences.size)
        endpoints.failed()
        assertEquals(aaaa.hostAddress, endpoints.select(hub).host)
    }

    @Test
    fun duplicateCallbacksAndAddressOrderPreserveTheSession() {
        val changes = mutableListOf<UnderlaySnapshot<Int>?>()
        val tracker = UnderlayTracker<Int> { changes.add(it) }

        tracker.available(1)
        tracker.capabilities(1, Transport.WIFI)
        tracker.properties(1, links)
        repeat(4) {
            tracker.available(1)
            tracker.capabilities(1, Transport.WIFI)
            tracker.properties(1, links.copy(addresses = setOf(ipv6, ipv4)))
        }

        assertEquals(listOf(UnderlaySnapshot(1, Transport.WIFI, links)), changes)
        assertEquals(listOf(Prefix.parse("192.168.1.7/24")), changes.single()?.lan)
    }

    @Test
    fun realLinkChangesAndHandoverPublishNewSessions() {
        val changes = mutableListOf<UnderlaySnapshot<Int>?>()
        val tracker = UnderlayTracker<Int> { changes.add(it) }
        val changedAddress = links.copy(addresses = setOf(ipv4, InetAddress.getByName("2001:db8::2") to 64))
        val changedLink = changedAddress.copy(mtu = 1440)

        tracker.available(1)
        tracker.properties(1, links)
        tracker.capabilities(1, Transport.WIFI)
        tracker.properties(1, changedAddress)
        tracker.properties(1, changedLink)
        tracker.available(2)
        tracker.lost(1)
        tracker.capabilities(1, Transport.OTHER)
        tracker.properties(1, links)
        tracker.properties(2, changedLink)
        tracker.capabilities(2, Transport.WIFI)
        tracker.lost(2)

        assertEquals(listOf(
            UnderlaySnapshot(1, Transport.WIFI, links),
            UnderlaySnapshot(1, Transport.WIFI, changedAddress),
            UnderlaySnapshot(1, Transport.WIFI, changedLink),
            null,
            UnderlaySnapshot(2, Transport.WIFI, changedLink),
            null,
        ), changes)
    }

    private data class Route(
        override val destination: InetAddress,
        override val prefixLength: Int,
        val gateway: String?,
    ) : UnderlayRoute {
        override val unicast = true
    }

    private fun route(address: String, bits: Int, gateway: String? = null) =
        Route(InetAddress.getByName(address), bits, gateway)
}

package org.slopworks.warren.vpn

import org.junit.Assert.assertEquals
import org.junit.Test
import org.slopworks.warren.agent.Prefix
import java.net.InetAddress

class UnderlayTest {
    private val ipv4 = InetAddress.getByName("192.168.1.7") to 24
    private val ipv6 = InetAddress.getByName("2001:db8::1") to 64
    private val links = UnderlayLinks("wlan0", setOf(ipv4, ipv6), emptySet(), 1500)

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
}

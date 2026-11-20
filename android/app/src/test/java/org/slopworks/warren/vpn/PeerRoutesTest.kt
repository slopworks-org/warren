package org.slopworks.warren.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.slopworks.warren.agent.AgentConfig
import org.slopworks.warren.agent.Pairs
import org.slopworks.warren.agent.Prefix

class PeerRoutesTest {
    @Test
    fun keepsAuthorizedRowsAndIdentitiesFromLanToCellular() {
        val lan = config(lanPeer + display + nas + remote + ssh)
        val wifi = PeerRoutes(lan, lan.eligibleLan(wifiSubnet))
        assertTrue(wifi.paths(emptySet(), wifi = true).none(PeerPath::direct))
        val proof = setOf("10.77.0.4", "10.77.0.6")
        val onWifi = wifi.paths(proof, wifi = true)
        assertEquals(listOf("NAS = Home", "Remote laptop", "SSH host"), onWifi.map(PeerPath::name))
        assertEquals(listOf("10.77.0.4", "10.77.0.5", "10.77.0.6"), onWifi.map(PeerPath::address))
        assertEquals(listOf("10.77.0.4"), onWifi.filter(PeerPath::direct).map(PeerPath::address))
        assertTrue(onWifi.first().wifi)
        assertTrue(wifi.paths(emptySet(), wifi = true).none(PeerPath::direct))

        val cellular = config(display + nas + remote + ssh)
        val onCellular = PeerRoutes(cellular, cellular.eligibleLan(emptyList())).paths(proof, wifi = false)
        assertEquals(onWifi.map { it.copy(direct = false, wifi = false) }, onCellular)
    }

    @Test
    fun replacesRowsAfterAclEditsAndRejectsObsoleteProof() {
        // The NAS is now port-scoped, and the SSH host lost all access.
        val changed = config(display + nas + remote)
        val proof = setOf("10.77.0.4", "10.77.0.6")
        val routes = PeerRoutes(changed, changed.eligibleLan(wifiSubnet)).paths(proof, wifi = true)
        assertEquals(listOf("10.77.0.4", "10.77.0.5"), routes.map(PeerPath::address))
        assertTrue(routes.none(PeerPath::direct))

        val empty = config(display + lanPeer)
        assertTrue(PeerRoutes(empty, empty.eligibleLan(wifiSubnet)).paths(proof, wifi = true).isEmpty())
    }

    @Test
    fun olderServerUsesOnlyCurrentlyEligibleLanCandidates() {
        val old = config(lanPeer)
        val proof = setOf("10.77.0.4")
        val wifi = PeerRoutes(old, old.eligibleLan(wifiSubnet))
        val peer = wifi.paths(emptySet(), wifi = true).single()
        assertEquals("10.77.0.4", peer.address)
        assertEquals(null, peer.name)
        assertFalse(peer.direct)
        assertTrue(wifi.paths(proof, wifi = true).single().direct)
        assertTrue(PeerRoutes(old, old.eligibleLan(emptyList())).paths(proof, wifi = false).isEmpty())
    }

    @Test
    fun validatesDisplayRowsWithoutInstallingLanRoutes() {
        val unnamed = config(display + "route_peer=$nasId 10.77.0.4\n")
        assertTrue(unnamed.lan.isEmpty())
        assertEquals(null, unnamed.routePeers?.single()?.name)
        for (malformed in listOf(nas, display + nas + nas, display + nas.replace("10.77.0.4", "10.77.0.1"),
            display + nas.replace("10.77.0.4", "1.1.1.1"), display + nas.repeat(257))) {
            assertThrows(IllegalArgumentException::class.java) { config(malformed) }
        }
    }

    private fun config(extra: String): AgentConfig = AgentConfig.parse(Pairs.parse(
        "version=42\ndevice_id=3\nname=Android\naddress=10.77.0.3/16\ncontrol=10.77.0.1:7180\n" +
            "peer=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc= hub.example:51820 10.77.0.0/16 25\n" + extra,
    ))

    private companion object {
        val wifiSubnet = listOf(Prefix.parse("192.168.0.2/24"))
        const val lanPeer = "lan_peer_v2=CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg= 192.168.0.3:9999 10.77.0.4/32 15\n"
        const val display = "route_peers=1\n"
        const val nasId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val nas = "route_peer=$nasId 10.77.0.4 NAS = Home\n"
        const val remote = "route_peer=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 10.77.0.5 Remote laptop\n"
        const val ssh = "route_peer=cccccccccccccccccccccccccccccccc 10.77.0.6 SSH host\n"
    }
}

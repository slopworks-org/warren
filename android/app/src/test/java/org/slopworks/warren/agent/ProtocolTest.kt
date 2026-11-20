package org.slopworks.warren.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolTest {
    @Test
    fun readsVersionedEnrollmentAndRejectsAnAmbiguousOrigin() {
        val qr = "warren://enroll?v=1&server=https%3A%2F%2Fhub.example%3A8443&token=$token"
        val enrollment = Enrollment.parse(qr)
        assertEquals("https://hub.example:8443", enrollment.server.toString())
        assertEquals((0..23).map(Int::toByte), enrollment.token.toList())
        assertThrows(IllegalArgumentException::class.java) { Enrollment.parse("$qr&server=https%3A%2F%2Fother.example") }
        assertThrows(IllegalArgumentException::class.java) { Enrollment.parse(qr.replace("https", "http")) }
    }

    @Test
    fun verifiesSignedReplyBeforeTrustingPeerAndRoutes() {
        val key = ByteArray(24) { it.toByte() }
        val nonce = "00112233445566778899aabbccddeeff"
        val mac = "0e7c70c7663b2cc2eb0e20a691f0b6a25e1b2bd0238eabccb86701f394b0904b"
        val wire = config + "mac=$mac\n"
        assertTrue(Registration.verify(key, nonce, Pairs.parse(wire)))
        assertFalse(Registration.verify(key, "11112233445566778899aabbccddeeff", Pairs.parse(wire)))
        assertFalse(Registration.verify(key, nonce, Pairs.parse(wire + "mac=$mac\n")))
        assertFalse(Registration.verify(key, nonce, Pairs.parse(wire.replace("hub.example", "other.example"))))
        val profile = AgentConfig.parse(Pairs.parse(wire))
        assertEquals(42uL, profile.version)
        assertEquals("fd77:6172:7265:6e00::a4d:3", profile.address.ip.probeAddress())
        assertFalse(profile.hub.allowed.single().contains(Ipv4.parse("1.1.1.1")))
        assertThrows(IllegalArgumentException::class.java) {
            AgentConfig.parse(Pairs.parse(config.replace("10.77.0.0/16", "0.0.0.0/0")))
        }
    }

    private companion object {
        const val token = "wrt_AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"
        const val config =
            "version=42\ndevice_id=3\nname=Android\naddress=10.77.0.3/16\ncontrol=10.77.0.1:7180\n" +
                "peer=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc= hub.example:51820 10.77.0.0/16 25\n"
    }
}

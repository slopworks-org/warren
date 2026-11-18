package org.slopworks.warren.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Test

class TilePhaseListenerTest {
    @Test
    fun rendersPhaseChangesDuringOneListeningSession() = runBlocking {
        val status = MutableStateFlow(VpnStatus(Phase.OFF))
        val rendered = mutableListOf<Phase>()
        val listener = TilePhaseListener(this, status, rendered::add)
        listener.start()
        listener.start()
        yield()

        val transitions = listOf(Phase.CONNECTING, Phase.CONNECTED, Phase.RECOVERING, Phase.CONNECTED,
            Phase.DISCONNECTING, Phase.OFF)
        for (phase in transitions) {
            status.value = VpnStatus(phase)
            yield()
        }
        status.value = VpnStatus(Phase.OFF, failed = true)
        yield()
        listener.stop()
        assertEquals(listOf(Phase.OFF) + transitions, rendered)
    }

    @Test
    fun stopsRenderingAndReadsCurrentPhaseWhenListeningRestarts() = runBlocking {
        val status = MutableStateFlow(VpnStatus(Phase.CONNECTING))
        val rendered = mutableListOf<Phase>()
        val listener = TilePhaseListener(this, status, rendered::add)
        listener.start()
        yield()
        listener.stop()
        listener.stop()
        status.value = VpnStatus(Phase.CONNECTED)
        yield()
        assertEquals(listOf(Phase.CONNECTING), rendered)

        listener.start()
        yield()
        assertEquals(listOf(Phase.CONNECTING, Phase.CONNECTED), rendered)
        status.value = VpnStatus(Phase.RECOVERING)
        listener.stop()
        yield()
        assertEquals(listOf(Phase.CONNECTING, Phase.CONNECTED), rendered)
    }
}

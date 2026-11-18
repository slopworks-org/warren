package org.slopworks.warren.vpn

internal enum class Phase { OFF, CONNECTING, CONNECTED, RECOVERING, DISCONNECTING }
internal data class VpnStatus(
    val phase: Phase,
    val peers: List<PeerPath>? = null,
    val failed: Boolean = false,
    val routesLoading: Boolean = false,
)

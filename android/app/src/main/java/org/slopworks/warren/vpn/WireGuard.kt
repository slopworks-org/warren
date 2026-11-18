package org.slopworks.warren.vpn

internal object WireGuard {
    init { System.loadLibrary("warrenwg") }

    external fun keyPair(): String?
    external fun open(fd: Int, local: Int, control: Int, port: Int): Boolean
    external fun setForwarding(enabled: Boolean)
    external fun socket(mesh: Boolean, ipv6: Boolean): Int
    external fun lanPort(): Int
    external fun setHub(config: String): Boolean
    external fun setLan(config: String, ips: String, deadlineNanos: Long): Boolean
    external fun directPaths(): String
    external fun close()
}

package org.slopworks.warren.ui

import androidx.compose.runtime.Immutable
import java.util.Collections

/** Snapshot supplied by the activity or its state holder. */
@Immutable
sealed interface WarrenUiState {
    data class Enrollment(
        val busy: Boolean = false,
        val error: WarrenError? = null,
        val replacing: Boolean = false,
        val pending: Boolean = false,
    ) : WarrenUiState

    /** Display after camera permission is granted. Null torch state means no torch is available. */
    data class Scanner(
        val torchEnabled: Boolean? = null,
        val busy: Boolean = false,
        val error: WarrenError? = null,
    ) : WarrenUiState

    data class Home(
        val status: WarrenVpnStatus,
        val routes: WarrenRoutes = WarrenRoutes.Unavailable,
        val details: WarrenConnectionDetails? = null,
        val canAddTile: Boolean = false,
        val error: WarrenError? = null,
    ) : WarrenUiState
}

/** Requests from the UI. The host reflects their actual results in [WarrenUiState]. */
enum class WarrenAction {
    CONNECT,
    DISCONNECT,
    SCAN_QR,
    CHOOSE_PHOTO,
    CLOSE_SCANNER,
    TOGGLE_TORCH,
    ADD_TILE,
    REPLACE_PROFILE,
    RETRY_ENROLLMENT,
    CANCEL_ENROLLMENT,
}

enum class WarrenVpnStatus {
    OFF,
    CONNECTING,
    CONNECTED,
    RECOVERING,
    DISCONNECTING,
}

/** Current route data. Only supply Ready when the active peer paths are known. */
@Immutable
sealed interface WarrenRoutes {
    data object Loading : WarrenRoutes
    data object Unavailable : WarrenRoutes

    class Ready(peers: Collection<WarrenPeer>) : WarrenRoutes {
        val peers: List<WarrenPeer> = Collections.unmodifiableList(peers.toList())

        override fun equals(other: Any?): Boolean = other is Ready && peers == other.peers

        override fun hashCode(): Int = peers.hashCode()
    }
}

/** [id] is a unique, stable key within a route snapshot. */
@Immutable
data class WarrenPeer(val id: String, val name: String?, val address: String, val path: WarrenPath)

enum class WarrenPath {
    DIRECT,
    DIRECT_WIFI,
    RELAY,
    UNAVAILABLE,
}

/** Only enable the optional rows when their behavior is supported by the host. */
@Immutable
data class WarrenConnectionDetails(
    val server: String,
    val splitTunnel: Boolean = false,
    val reconnects: Boolean = false,
)

enum class WarrenError {
    CAMERA_DENIED,
    CAMERA_UNAVAILABLE,
    PHOTO_UNREADABLE,
    QR_NOT_FOUND,
    INVALID_CODE,
    EXPIRED_CODE,
    ENROLLMENT_FAILED,
    SERVER_UNREACHABLE,
    SERVER_UPGRADE,
    VPN_DENIED,
    VPN_FAILED,
    TILE_FAILED,
}

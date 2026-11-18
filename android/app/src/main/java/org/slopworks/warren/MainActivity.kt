package org.slopworks.warren

import android.Manifest
import android.app.Activity
import android.app.Application
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.SideEffect
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.slopworks.warren.agent.AgentClient
import org.slopworks.warren.agent.AgentException
import org.slopworks.warren.agent.AgentFailure
import org.slopworks.warren.agent.Enrollment
import org.slopworks.warren.agent.PendingEnrollment
import org.slopworks.warren.agent.Profile
import org.slopworks.warren.agent.ProfileStore
import org.slopworks.warren.ui.WarrenAction
import org.slopworks.warren.ui.WarrenApp
import org.slopworks.warren.ui.WarrenConnectionDetails
import org.slopworks.warren.ui.WarrenError
import org.slopworks.warren.ui.WarrenPath
import org.slopworks.warren.ui.WarrenPeer
import org.slopworks.warren.ui.WarrenRoutes
import org.slopworks.warren.ui.WarrenUiState
import org.slopworks.warren.ui.WarrenVpnStatus
import org.slopworks.warren.vpn.Phase
import org.slopworks.warren.vpn.VpnStatus
import org.slopworks.warren.vpn.WarrenVpnService

class MainActivity : ComponentActivity() {
    private val model: WarrenModel by viewModels()
    private var camera: CameraScan? = null
    private val permission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { allowed ->
        if (model.screen.value.canReadCode) {
            model.update { copy(scanner = allowed, error = if (allowed) null else WarrenError.CAMERA_DENIED) }
        }
    }
    private val photo = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) model.enrollFromPhoto(uri)
    }
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) connect()
        else model.error(WarrenError.VPN_DENIED)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val screen = model.screen.collectAsStateWithLifecycle().value
            val vpn = WarrenVpnService.status.collectAsStateWithLifecycle().value
            SideEffect {
                // The live preview can show a still-valid enrollment token.
                if (screen.scanner) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
            WarrenApp(state = screen.ui(vpn), onAction = ::onAction, cameraPreview = {
                if (screen.scanner) {
                    ScanPreview(
                        canScan = !screen.busy && screen.error != WarrenError.CAMERA_UNAVAILABLE,
                        onCamera = { camera = it },
                        onTorch = { value -> model.update { copy(torch = value) } },
                        onCode = model::enrollFromCamera,
                        onUnavailable = { model.error(WarrenError.CAMERA_UNAVAILABLE) },
                    )
                }
            })
        }
    }

    private fun onAction(action: WarrenAction) {
        when (action) {
            WarrenAction.CONNECT -> {
                if (!model.screen.value.canConnect) return
                model.error(null)
                val request = VpnService.prepare(this)
                if (request == null) connect() else vpnConsent.launch(request)
            }
            WarrenAction.DISCONNECT -> {
                model.error(null)
                if (runCatching { WarrenVpnService.disconnect(this) }.isFailure) model.error(WarrenError.VPN_FAILED)
            }
            WarrenAction.SCAN_QR -> {
                if (!model.screen.value.canReadCode) return
                if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                    model.update { copy(scanner = true, torch = null, error = null) }
                } else {
                    permission.launch(Manifest.permission.CAMERA)
                }
            }
            WarrenAction.CHOOSE_PHOTO -> {
                if (!model.screen.value.canReadCode) return
                model.error(null)
                photo.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
            }
            WarrenAction.CLOSE_SCANNER -> model.update { copy(scanner = false, error = null, torch = null) }
            WarrenAction.TOGGLE_TORCH -> camera?.toggleTorch()
            WarrenAction.ADD_TILE -> Unit
            WarrenAction.REPLACE_PROFILE -> model.replaceProfile()
            WarrenAction.RETRY_ENROLLMENT -> model.retryEnrollment()
            WarrenAction.CANCEL_ENROLLMENT -> model.cancelEnrollment()
        }
    }

    private fun connect() {
        if (!model.screen.value.canConnect) return
        if (runCatching { WarrenVpnService.connect(this) }.isFailure) model.error(WarrenError.VPN_FAILED)
    }

}

internal data class Screen(
    val profile: Profile? = null,
    val busy: Boolean = true,
    val replacing: Boolean = false,
    val pending: Boolean = false,
    val scanner: Boolean = false,
    val torch: Boolean? = null,
    val error: WarrenError? = null,
) {
    val canReadCode get() = !busy && !pending && (profile == null || replacing)
    val canConnect get() = !busy && !replacing && profile != null

    fun ui(vpn: VpnStatus): WarrenUiState {
        if (profile == null || replacing) {
            return if (scanner) WarrenUiState.Scanner(torch, busy, error)
            else WarrenUiState.Enrollment(busy, error, replacing, pending)
        }
        val paths = vpn.peers?.map { peer ->
            WarrenPeer(peer.id, peer.name, peer.address, when {
                peer.direct && peer.wifi -> WarrenPath.DIRECT_WIFI
                peer.direct -> WarrenPath.DIRECT
                else -> WarrenPath.RELAY
            })
        }
        return WarrenUiState.Home(
            status = WarrenVpnStatus.valueOf(vpn.phase.name),
            routes = when {
                paths != null -> WarrenRoutes.Ready(paths)
                vpn.routesLoading || vpn.phase == Phase.CONNECTING || vpn.phase == Phase.RECOVERING -> WarrenRoutes.Loading
                else -> WarrenRoutes.Unavailable
            },
            details = WarrenConnectionDetails(profile.server, splitTunnel = true, reconnects = true),
            error = error ?: if (vpn.failed) WarrenError.VPN_FAILED else null,
        )
    }
}

class WarrenModel(private val application: Application) : AndroidViewModel(application) {
    private val store = ProfileStore(application)
    internal val screen = MutableStateFlow(Screen())

    init {
        viewModelScope.launch {
            val loaded = withContext(Dispatchers.IO) { runCatching { store.enrollmentState() } }
            val (profile, pending) = loaded.getOrNull() ?: (null to false)
            update { copy(profile = profile, busy = pending, pending = pending, replacing = pending && profile != null,
                error = if (loaded.isFailure) WarrenError.ENROLLMENT_FAILED else null) }
            if (profile != null && WarrenVpnService.status.value.phase == Phase.OFF) {
                runCatching { WarrenVpnService.restore(application) }
            }
            if (pending) submitPending()
        }
    }

    internal fun update(change: Screen.() -> Screen) { screen.value = screen.value.change() }
    internal fun error(value: WarrenError?) = update { copy(error = value) }

    internal fun replaceProfile() {
        if (screen.value.canConnect) update { copy(replacing = true, error = null) }
    }

    internal fun retryEnrollment() {
        if (screen.value.busy || !screen.value.pending) return
        update { copy(busy = true, error = null) }
        viewModelScope.launch { submitPending() }
    }

    internal fun cancelEnrollment() {
        if (screen.value.busy) return
        update { copy(busy = true) }
        viewModelScope.launch {
            val cleared = withContext(Dispatchers.IO) { runCatching { store.cancelEnrollment() } }
            if (cleared.isSuccess) {
                update { copy(busy = false, pending = false, replacing = false, error = null) }
            } else {
                enrollmentFailed(WarrenError.ENROLLMENT_FAILED)
            }
        }
    }

    internal fun enrollFromCamera(code: String) {
        if (!screen.value.canReadCode || !screen.value.scanner) return
        update { copy(busy = true, error = null) }
        viewModelScope.launch { enroll(code) }
    }

    internal fun enrollFromPhoto(uri: Uri) {
        if (!screen.value.canReadCode) return
        update { copy(busy = true, error = null) }
        viewModelScope.launch {
            val code = try {
                scanPhoto(application, uri)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                update { copy(busy = false, error = WarrenError.PHOTO_UNREADABLE) }
                return@launch
            }
            if (code == null) update { copy(busy = false, error = WarrenError.QR_NOT_FOUND) }
            else enroll(code)
        }
    }

    private suspend fun enroll(code: String) {
        val data = runCatching { Enrollment.parse(code) }.getOrNull()
        if (data == null) {
            update { copy(busy = false, scanner = false, torch = null, error = WarrenError.INVALID_CODE) }
            return
        }
        try {
            withContext(Dispatchers.IO) { store.beginEnrollment(AgentClient.prepareEnrollment(data)) }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            enrollmentFailed(WarrenError.ENROLLMENT_FAILED)
            return
        } finally {
            data.token.fill(0)
        }
        update { copy(pending = true, scanner = false, torch = null) }
        submitPending()
    }

    private suspend fun submitPending() {
        var pending: PendingEnrollment? = null
        try {
            val transaction = withContext(Dispatchers.IO) { store.pendingEnrollment() }
            pending = transaction
            val profile = AgentClient.enroll(transaction)
            WarrenVpnService.replaceProfile(store, transaction, profile)
            update { copy(profile = profile, busy = false, pending = false, replacing = false,
                error = null) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: AgentException) {
            enrollmentFailed(when (e.failure) {
                AgentFailure.TOKEN -> WarrenError.EXPIRED_CODE
                AgentFailure.NETWORK -> WarrenError.SERVER_UNREACHABLE
                AgentFailure.SERVER_UPGRADE -> WarrenError.SERVER_UPGRADE
                else -> WarrenError.ENROLLMENT_FAILED
            })
        } catch (_: Exception) {
            enrollmentFailed(WarrenError.ENROLLMENT_FAILED)
        } finally {
            pending?.token?.fill(0)
        }
    }

    private fun enrollmentFailed(error: WarrenError) =
        update { copy(busy = false, scanner = false, torch = null, error = error) }
}

package org.slopworks.warren.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier

/**
 * Warren's UI. The host owns permission, picker and VPN interactions and reflects their results
 * in [state]. Provide the live [cameraPreview] for [WarrenUiState.Scanner]. Its container fills
 * the scanner viewfinder and clips to the viewfinder shape.
 */
@Composable
fun WarrenApp(
    state: WarrenUiState,
    onAction: (WarrenAction) -> Unit,
    modifier: Modifier = Modifier,
    cameraPreview: @Composable () -> Unit = {},
) {
    WarrenTheme {
        Surface(modifier.fillMaxSize()) {
            Box(Modifier.fillMaxSize().safeDrawingPadding()) {
                when (state) {
                    is WarrenUiState.Enrollment -> EnrollmentScreen(state, onAction)
                    is WarrenUiState.Scanner -> ScannerScreen(state, onAction, cameraPreview)
                    is WarrenUiState.Home -> PairedScreens(state, onAction)
                }
            }
        }
    }
}

@Composable
private fun PairedScreens(state: WarrenUiState.Home, onAction: (WarrenAction) -> Unit) {
    var routesOpen by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(state.status) {
        if (state.status != WarrenVpnStatus.CONNECTED) routesOpen = false
    }
    val showRoutes = routesOpen && state.status == WarrenVpnStatus.CONNECTED
    BackHandler(enabled = showRoutes) { routesOpen = false }

    if (showRoutes) {
        RoutesScreen(state.routes, onBack = { routesOpen = false })
    } else {
        HomeScreen(state, onAction, onRoutes = { routesOpen = true })
    }
}

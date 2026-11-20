package org.slopworks.warren

import android.content.Context
import android.graphics.ImageDecoder
import android.net.Uri
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.TorchState
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal class CameraScan(private val camera: Camera) {
    fun toggleTorch() {
        camera.cameraControl.enableTorch(camera.cameraInfo.torchState.value != TorchState.ON)
    }
}

private fun qrScanner() = BarcodeScanning.getClient(
    BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build(),
)

@Composable
@androidx.annotation.OptIn(ExperimentalGetImage::class)
internal fun ScanPreview(
    canScan: Boolean,
    onCamera: (CameraScan?) -> Unit,
    onTorch: (Boolean?) -> Unit,
    onCode: (String) -> Unit,
    onUnavailable: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current
    val enabled = rememberUpdatedState(canScan)
    val code = rememberUpdatedState(onCode)
    val view = remember(context) {
        PreviewView(context).apply {
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }
    AndroidView(factory = { view }, modifier = Modifier.fillMaxSize())
    DisposableEffect(lifecycle, view) {
        val provider = ProcessCameraProvider.getInstance(context)
        val executor = context.mainExecutor
        val scanner = qrScanner()
        val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
        val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
        var live = true
        var camera: Camera? = null
        val torchObserver = androidx.lifecycle.Observer<Int> { onTorch(it == TorchState.ON) }
        provider.addListener({
            if (live) {
                try {
                    analysis.setAnalyzer(executor) { frame ->
                        val image = frame.image
                        if (!live || !enabled.value || image == null) {
                            frame.close()
                        } else {
                            scanner.process(InputImage.fromMediaImage(image, frame.imageInfo.rotationDegrees))
                                .addOnSuccessListener(executor) { results ->
                                    if (live && enabled.value) results.firstNotNullOfOrNull { it.rawValue }?.let(code.value)
                                }
                                .addOnCompleteListener(executor) { frame.close() }
                        }
                    }
                    camera = provider.get().bindToLifecycle(lifecycle, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                    onCamera(CameraScan(checkNotNull(camera)))
                    val info = camera.cameraInfo
                    if (info.hasFlashUnit()) info.torchState.observe(lifecycle, torchObserver)
                    else onTorch(null)
                } catch (_: Exception) {
                    onUnavailable()
                }
            }
        }, executor)
        onDispose {
            live = false
            onCamera(null)
            camera?.cameraInfo?.torchState?.removeObserver(torchObserver)
            analysis.clearAnalyzer()
            if (provider.isDone) runCatching { provider.get().unbind(preview, analysis) }
            scanner.close()
        }
    }
}

internal suspend fun scanPhoto(context: Context, uri: Uri): String? {
    val bitmap = withContext(Dispatchers.IO) {
        ImageDecoder.decodeBitmap(ImageDecoder.createSource(context.contentResolver, uri)) { decoder, info, _ ->
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            val width = info.size.width
            val height = info.size.height
            val max = maxOf(width, height)
            if (max > 3072) decoder.setTargetSize((width * 3072L / max).toInt().coerceAtLeast(1),
                (height * 3072L / max).toInt().coerceAtLeast(1))
        }
    }
    return suspendCancellableCoroutine { continuation ->
        val scanner = qrScanner()
        scanner.process(InputImage.fromBitmap(bitmap, 0)).addOnCompleteListener(context.mainExecutor) { task ->
            scanner.close()
            bitmap.recycle()
            if (!continuation.isActive) return@addOnCompleteListener
            if (task.isSuccessful) continuation.resume(task.result.firstNotNullOfOrNull { it.rawValue })
            else continuation.resumeWithException(task.exception ?: IllegalStateException())
        }
    }
}

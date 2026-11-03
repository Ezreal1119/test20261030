package com.patrick.test20261030

import android.content.Context
import android.graphics.ImageFormat
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CameraMetadata
import android.hardware.camera2.CaptureFailure
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.util.Size
import android.view.Surface
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

class HighResolutionJpegCapture(
    context: Context,
    private val cameraId: String,
    private val sizes: List<Size>,
) {
    private val manager = context.getSystemService(CameraManager::class.java)
    private val thread = HandlerThread("pod-hires-capture").apply { start() }
    private val handler = Handler(thread.looper)
    private val finished = AtomicBoolean(false)
    private var device: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private var sizeIndex = 0
    private var openAttempts = 0

    fun capture(destination: File, onComplete: (error: String?) -> Unit) {
        openCamera(destination, onComplete)
    }

    fun cancel() {
        finish(device, {}, "Cancelled.")
    }

    private fun openCamera(destination: File, onComplete: (String?) -> Unit) {
        openAttempts += 1
        try {
            manager.openCamera(cameraId, object : CameraDevice.StateCallback() {
                override fun onOpened(camera: CameraDevice) {
                    if (finished.get()) {
                        camera.close()
                        return
                    }
                    device = camera
                    tryNextSize(destination, onComplete)
                }

                override fun onDisconnected(camera: CameraDevice) {
                    finish(camera, onComplete, "Camera disconnected.")
                }

                override fun onError(camera: CameraDevice, error: Int) {
                    camera.close()
                    if (error == CameraDevice.StateCallback.ERROR_CAMERA_IN_USE && openAttempts < 3) {
                        handler.postDelayed({ openCamera(destination, onComplete) }, 400)
                    } else {
                        finish(null, onComplete, "Camera open failed with error $error.")
                    }
                }
            }, handler)
        } catch (error: Exception) {
            finish(null, onComplete, error.message ?: error.javaClass.simpleName)
        }
    }

    private fun tryNextSize(destination: File, onComplete: (String?) -> Unit) {
        if (finished.get()) return
        if (sizeIndex >= sizes.size) {
            finish(device, onComplete, "The camera rejected 6000x8000 and 8000x6000.")
            return
        }
        val size = sizes[sizeIndex]
        reader?.close()
        val imageReader = ImageReader.newInstance(size.width, size.height, ImageFormat.JPEG, 1)
        reader = imageReader
        imageReader.setOnImageAvailableListener({ source ->
            val image = source.acquireNextImage() ?: return@setOnImageAvailableListener
            try {
                val buffer = image.planes[0].buffer
                val bytes = ByteArray(buffer.remaining())
                buffer.get(bytes)
                FileOutputStream(destination).use { it.write(bytes) }
                finish(device, onComplete, null)
            } catch (error: Exception) {
                finish(device, onComplete, error.message ?: "Could not write the JPEG.")
            } finally {
                image.close()
            }
        }, handler)
        val output = OutputConfiguration(imageReader.surface)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            output.addSensorPixelModeUsed(CameraMetadata.SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION)
        }
        val configuration = SessionConfiguration(
            SessionConfiguration.SESSION_REGULAR,
            listOf(output),
            { command -> handler.post(command) },
            object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(captureSession: CameraCaptureSession) {
                    session = captureSession
                    submitStillCapture(captureSession, imageReader.surface, size, destination, onComplete)
                }

                override fun onConfigureFailed(captureSession: CameraCaptureSession) {
                    sizeIndex += 1
                    tryNextSize(destination, onComplete)
                }
            },
        )
        try {
            device?.createCaptureSession(configuration)
        } catch (error: Exception) {
            sizeIndex += 1
            tryNextSize(destination, onComplete)
        }
    }

    private fun submitStillCapture(
        captureSession: CameraCaptureSession,
        surface: Surface,
        size: Size,
        destination: File,
        onComplete: (String?) -> Unit,
    ) {
        val camera = device ?: return
        try {
            val request = camera.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE).apply {
                addTarget(surface)
                set(CaptureRequest.JPEG_QUALITY, 95.toByte())
                set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
            }
            captureSession.capture(
                request.build(),
                object : CameraCaptureSession.CaptureCallback() {
                    override fun onCaptureFailed(
                        session: CameraCaptureSession,
                        request: CaptureRequest,
                        failure: CaptureFailure,
                    ) {
                        sizeIndex += 1
                        if (sizeIndex < sizes.size) {
                            tryNextSize(destination, onComplete)
                        } else {
                            finish(device, onComplete, "Still capture failed for ${size.width}x${size.height}.")
                        }
                    }
                },
                handler,
            )
        } catch (error: Exception) {
            sizeIndex += 1
            if (sizeIndex < sizes.size) tryNextSize(destination, onComplete)
            else finish(device, onComplete, error.message ?: "Still capture failed.")
        }
    }

    private fun finish(camera: CameraDevice?, onComplete: (String?) -> Unit, error: String?) {
        if (!finished.compareAndSet(false, true)) return
        runCatching { session?.close() }
        runCatching { reader?.close() }
        runCatching { camera?.close() }
        thread.quitSafely()
        onComplete(error)
    }
}

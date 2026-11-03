package com.patrick.test20261030

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraMetadata
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Size
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.camera2.interop.Camera2CameraInfo
import androidx.camera.camera2.interop.ExperimentalCamera2Interop
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.patrick.test20261030.databinding.ActivityPodCameraBinding
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.time.Instant
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.roundToLong

class PodCameraActivity : AppCompatActivity() {
    private lateinit var binding: ActivityPodCameraBinding
    private val mainHandler = Handler(Looper.getMainLooper())
    private var cameraExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private var imageCapture: ImageCapture? = null
    private var selectedSize: Size? = null
    private var rearCameraId: String = ""
    private var hardwareLevel: String = ""
    private var afModes: List<String> = emptyList()
    private var pictureAutofocus: Boolean = false
    private var sensorArray: String = ""
    private var supportedJpegSizes: List<String> = emptyList()
    private var maximumJpegSizes: List<String> = emptyList()
    private var ultraHighResolution: String = "NOT TESTED"
    private var maximumSensorArray: String = "NOT TESTED"
    private var sizeSource: String = "NOT TESTED"
    private var cameraReady: Boolean = false
    private var cameraError: String = "NOT TESTED"
    private var captureInFlight: Boolean = false
    private var activeCapture: HighResolutionJpegCapture? = null
    private var batchRemaining: Int = 0

    private val requestCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) inspectAndStart() else {
            cameraError = "Camera permission was denied."
            render()
        }
    }
    private val createCsv = registerForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri ->
        if (uri != null) writeExport(uri, buildCsv())
    }
    private val createJson = registerForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null) writeExport(uri, buildJson())
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPodCameraBinding.inflate(layoutInflater)
        setContentView(binding.root)
        enableEdgeToEdge()
        ViewCompat.setOnApplyWindowInsetsListener(binding.podRoot) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        PodSessionHolder.restore(sessionFile())
        binding.buttonPodCapture.setOnClickListener { captureOne() }
        binding.buttonPodBatch.setOnClickListener { startBatch() }
        binding.buttonPodCancel.setOnClickListener { PodSessionHolder.batchCancel = true }
        binding.buttonPodView.setOnClickListener { viewSample() }
        binding.buttonPodShare.setOnClickListener { shareSample() }
        binding.buttonPodCsv.setOnClickListener { createCsv.launch("dt610-pod-camera.csv") }
        binding.buttonPodJson.setOnClickListener { createJson.launch("dt610-pod-camera.json") }
        binding.buttonLegibilityPass.setOnClickListener { setLegibility("PASS") }
        binding.buttonLegibilityFail.setOnClickListener { setLegibility("FAIL") }
        binding.buttonLegibilityClear.setOnClickListener { setLegibility("NOT REVIEWED") }
        binding.buttonPodSpec.setOnClickListener { confirmSpec() }
        binding.buttonPodClear.setOnClickListener { clearResults() }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            inspectAndStart()
        } else {
            requestCamera.launch(Manifest.permission.CAMERA)
        }
        render()
    }

    override fun onDestroy() {
        mainHandler.removeCallbacksAndMessages(null)
        cameraExecutor.shutdown()
        super.onDestroy()
    }

    private fun inspectAndStart() {
        try {
            val manager = getSystemService(CAMERA_SERVICE) as android.hardware.camera2.CameraManager
            var bestPixels = -1L
            var bestId: String? = null
            var bestDefault = emptyList<Size>()
            var bestMaximum = emptyList<Size>()
            var bestCharacteristics: CameraCharacteristics? = null
            for (cameraId in manager.cameraIdList) {
                val chars = manager.getCameraCharacteristics(cameraId)
                if (chars.get(CameraCharacteristics.LENS_FACING) != CameraCharacteristics.LENS_FACING_BACK) continue
                val defaults = jpegSizes(chars, maximumResolution = false)
                val maximums = jpegSizes(chars, maximumResolution = true)
                val pixels = (defaults + maximums).maxOfOrNull { it.width.toLong() * it.height.toLong() } ?: 0L
                if (pixels > bestPixels) {
                    bestPixels = pixels
                    bestId = cameraId
                    bestDefault = defaults
                    bestMaximum = maximums
                    bestCharacteristics = chars
                }
            }
            val id = bestId
            val characteristics = bestCharacteristics
            if (id == null || characteristics == null) {
                cameraError = "No rear-facing camera was found."
                cameraReady = false
                render()
                return
            }
            rearCameraId = id
            hardwareLevel = hardwareName(characteristics.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL))
            val modes = characteristics.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES)?.toList().orEmpty()
            afModes = modes.map { afName(it) }
            pictureAutofocus = modes.any {
                it == CameraMetadata.CONTROL_AF_MODE_AUTO ||
                    it == CameraMetadata.CONTROL_AF_MODE_MACRO ||
                    it == CameraMetadata.CONTROL_AF_MODE_CONTINUOUS_PICTURE
            }
            val array = characteristics.get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE)
            sensorArray = if (array == null) "not reported" else "${array.width} x ${array.height}"
            maximumSensorArray = maximumSensorSize(characteristics)
            val capabilities = characteristics.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES)
            ultraHighResolution = if (
                capabilities?.contains(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR) == true
            ) {
                "YES"
            } else {
                "NO"
            }
            supportedJpegSizes = bestDefault.map { "${it.width}x${it.height}" }
            maximumJpegSizes = bestMaximum.map { "${it.width}x${it.height}" }
            val chosen = PodCameraRules.chooseJpegSize((bestDefault + bestMaximum).map { it.width to it.height })
            if (chosen == null) {
                cameraError = "The rear camera did not report a JPEG output size."
                cameraReady = false
                render()
                return
            }
            selectedSize = Size(chosen.first, chosen.second)
            sizeSource = if (bestMaximum.any { it.width == chosen.first && it.height == chosen.second }) {
                "maximum-resolution JPEG list"
            } else {
                "default JPEG list"
            }
            startCamera(selectedSize!!)
        } catch (error: Exception) {
            cameraReady = false
            cameraError = error.message ?: error.javaClass.simpleName
            render()
        }
    }

    private fun jpegSizes(characteristics: CameraCharacteristics, maximumResolution: Boolean): List<Size> {
        val map = if (maximumResolution) {
            if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.S) return emptyList()
            characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP_MAXIMUM_RESOLUTION)
        } else {
            characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
        }
        return map?.getOutputSizes(android.graphics.ImageFormat.JPEG)?.toList().orEmpty()
    }

    private fun maximumSensorSize(characteristics: CameraCharacteristics): String {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.S) return "not available on this Android version"
        val size = characteristics.get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE_MAXIMUM_RESOLUTION)
        return if (size == null) "not reported" else "${size.width} x ${size.height}"
    }

    @OptIn(ExperimentalCamera2Interop::class)
    private fun startCamera(size: Size) {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            try {
                val provider = future.get()
                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = binding.podPreview.surfaceProvider
                }
                val selector = ResolutionSelector.Builder()
                    .setAllowedResolutionMode(ResolutionSelector.PREFER_HIGHER_RESOLUTION_OVER_CAPTURE_RATE)
                    .setResolutionStrategy(
                        ResolutionStrategy(size, ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER),
                    )
                    .setResolutionFilter { supportedSizes, _ ->
                        val exact = supportedSizes.filter { it.width == size.width && it.height == size.height }
                        if (exact.isNotEmpty()) {
                            exact
                        } else {
                            listOfNotNull(supportedSizes.maxByOrNull { it.width.toLong() * it.height.toLong() })
                        }
                    }
                    .build()
                val capture = ImageCapture.Builder()
                    .setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY)
                    .setJpegQuality(JPEG_QUALITY)
                    .setResolutionSelector(selector)
                    .build()
                val cameraSelector = CameraSelector.Builder()
                    .addCameraFilter { cameras ->
                        cameras.filter { Camera2CameraInfo.from(it).cameraId == rearCameraId }
                    }
                    .build()
                imageCapture = capture
                provider.unbindAll()
                provider.bindToLifecycle(this, cameraSelector, preview, capture)
                cameraReady = true
                cameraError = ""
            } catch (error: Exception) {
                cameraReady = false
                cameraError = error.message ?: error.javaClass.simpleName
            }
            render()
        }, ContextCompat.getMainExecutor(this))
    }

    private fun captureOne() {
        if (captureInFlight) return
        startShot("manual") { }
    }

    private fun startBatch() {
        if (captureInFlight || batchRemaining > 0) return
        if (rearCameraId.isBlank()) {
            Toast.makeText(this, "Camera is not ready.", Toast.LENGTH_SHORT).show()
            return
        }
        PodSessionHolder.batchCancel = false
        batchRemaining = BATCH_COUNT
        runNextBatchShot()
    }

    private fun runNextBatchShot() {
        if (PodSessionHolder.batchCancel || batchRemaining <= 0) {
            batchRemaining = 0
            render()
            return
        }
        batchRemaining -= 1
        startShot("automated") { runNextBatchShot() }
    }

    private fun startShot(mode: String, onDone: () -> Unit) {
        if (rearCameraId.isBlank()) {
            record(
                mode = mode,
                t0 = SystemClock.elapsedRealtimeNanos(),
                t1 = SystemClock.elapsedRealtimeNanos(),
                status = "FAILED",
                error = if (cameraError.isBlank()) "Camera is not ready." else cameraError,
                file = null,
                width = null,
                height = null,
            )
            onDone()
            return
        }
        captureInFlight = true
        render()
        val file = File(outputDir(), "pod-${System.currentTimeMillis()}-$mode.jpg")
        val t0 = SystemClock.elapsedRealtimeNanos()
        val startedAt = Instant.now().toString()
        val finished = AtomicBoolean(false)
        val capture = HighResolutionJpegCapture(this, rearCameraId, TRIAL_SIZES)
        activeCapture = capture
        val timeout = Runnable {
            if (finished.compareAndSet(false, true)) {
                capture.cancel()
                captureInFlight = false
                record(
                    mode = mode,
                    t0 = t0,
                    t1 = SystemClock.elapsedRealtimeNanos(),
                    status = "FAILED",
                    error = "Timed out after ${TIMEOUT_MS / 1000} s before a JPEG was saved.",
                    file = null,
                    width = null,
                    height = null,
                    startedAt = startedAt,
                )
                restorePreview()
                onDone()
            }
        }
        mainHandler.postDelayed(timeout, TIMEOUT_MS)
        val begin = Runnable {
            capture.capture(file) { error ->
                val t1 = SystemClock.elapsedRealtimeNanos()
                if (!finished.compareAndSet(false, true)) return@capture
                mainHandler.removeCallbacks(timeout)
                mainHandler.post {
                    captureInFlight = false
                    activeCapture = null
                    val checked = if (error == null) checkSavedFile(file) else null
                    if (checked == null) {
                        record(
                            mode,
                            t0,
                            t1,
                            "FAILED",
                            error ?: "Saved file was missing, empty, or unreadable.",
                            null,
                            null,
                            null,
                            startedAt,
                        )
                    } else {
                        val requested = "${TRIAL_SIZES.joinToString { "${it.width}x${it.height}" }}"
                        val note = if (checked.first == 6000 && checked.second == 8000 || checked.first == 8000 && checked.second == 6000) {
                            ""
                        } else {
                            "Camera returned ${checked.first}x${checked.second} after a request for $requested."
                        }
                        record(mode, t0, t1, "SAVED", note, file, checked.first, checked.second, startedAt)
                        if (mode == "manual") PodSessionHolder.samplePath = file.absolutePath
                    }
                    restorePreview()
                    onDone()
                }
            }
        }
        if (cameraReady) {
            val future = ProcessCameraProvider.getInstance(this)
            future.addListener({
                runCatching { future.get().unbindAll() }
                imageCapture = null
                cameraReady = false
                mainHandler.postDelayed(begin, 300)
            }, ContextCompat.getMainExecutor(this))
        } else {
            begin.run()
        }
    }

    private fun restorePreview() {
        val size = selectedSize ?: return
        if (batchRemaining > 0 && !PodSessionHolder.batchCancel) return
        startCamera(size)
    }

    private fun checkSavedFile(file: File): Pair<Int, Int>? {
        if (!file.exists() || file.length() <= 0L) return null
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        return bounds.outWidth to bounds.outHeight
    }

    private fun record(
        mode: String,
        t0: Long,
        t1: Long,
        status: String,
        error: String,
        file: File?,
        width: Int?,
        height: Int?,
        startedAt: String = Instant.now().toString(),
    ) {
        val record = CaptureRecord(
            id = PodSessionHolder.records.size + 1,
            mode = mode,
            startedAt = startedAt,
            endedAt = Instant.now().toString(),
            t0Nanos = t0,
            t1Nanos = t1,
            durationMs = (t1 - t0) / 1_000_000.0,
            status = status,
            error = error,
            fileName = file?.name.orEmpty(),
            fileBytes = file?.takeIf { it.exists() }?.length(),
            width = width,
            height = height,
        )
        PodSessionHolder.records.add(record)
        PodSessionHolder.persist(sessionFile())
        render()
    }

    private fun setLegibility(value: String) {
        PodSessionHolder.legibility = value
        PodSessionHolder.persist(sessionFile())
        render()
    }

    private fun confirmSpec() {
        if (PodSessionHolder.specConfirmed) {
            AlertDialog.Builder(this)
                .setTitle("Clear specification confirmation")
                .setMessage("This removes the operator confirmation. The app still cannot read the product specification itself.")
                .setPositiveButton("Clear") { _, _ ->
                    PodSessionHolder.specConfirmed = false
                    PodSessionHolder.specConfirmedAt = null
                    PodSessionHolder.persist(sessionFile())
                    render()
                }
                .setNegativeButton("Cancel", null)
                .show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle("Confirm product specification")
            .setMessage("Confirm only after reading an authoritative DT610 specification that states the rear camera is at least 13 MP. JPEG size is not that specification.")
            .setPositiveButton("Confirm") { _, _ ->
                PodSessionHolder.specConfirmed = true
                PodSessionHolder.specConfirmedAt = Instant.now().toString()
                PodSessionHolder.persist(sessionFile())
                render()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun clearResults() {
        AlertDialog.Builder(this)
            .setTitle("Clear measured results")
            .setMessage("This clears the capture log and legibility mark. It does not delete exported files.")
            .setPositiveButton("Clear") { _, _ ->
                PodSessionHolder.records.clear()
                PodSessionHolder.legibility = "NOT REVIEWED"
                PodSessionHolder.samplePath = null
                PodSessionHolder.batchCancel = true
                batchRemaining = 0
                PodSessionHolder.persist(sessionFile())
                binding.imagePodThumb.setImageDrawable(null)
                render()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun render() {
        val size = selectedSize
        val qualified = size != null && PodCameraRules.pixels(size.width, size.height) >= PodCameraRules.MIN_PIXELS
        val cameraRows = mutableListOf(
            "Rear camera ID" to rearCameraId.ifBlank { "NOT TESTED" },
            "Hardware level" to hardwareLevel.ifBlank { "NOT TESTED" },
            "AF modes" to if (afModes.isEmpty()) "NOT TESTED" else afModes.joinToString("\n"),
            "Still-picture AF" to if (rearCameraId.isBlank()) "NOT TESTED" else if (pictureAutofocus) "SUPPORTED" else "NOT SUPPORTED",
            "HAL sensor pixel array" to sensorArray.ifBlank { "NOT TESTED" },
            "Maximum-resolution sensor array" to maximumSensorArray,
            "Ultra-high-resolution capability" to ultraHighResolution,
            "Default JPEG sizes" to if (supportedJpegSizes.isEmpty()) "NOT TESTED" else supportedJpegSizes.joinToString("\n"),
            "Maximum-resolution JPEG sizes" to if (maximumJpegSizes.isEmpty()) "NONE REPORTED" else maximumJpegSizes.joinToString("\n"),
            "Selected JPEG size" to if (size == null) {
                "Not available"
            } else {
                "${size.width} x ${size.height}\n${PodCameraRules.formatMp(size.width, size.height)} MP\n${PodCameraRules.pixels(size.width, size.height)} pixels\nSource: $sizeSource"
            },
            "13,000,000-pixel JPEG" to if (size == null) "NOT TESTED" else if (qualified) "AVAILABLE" else "NOT AVAILABLE",
            "Product spec" to if (PodSessionHolder.specConfirmed) "CONFIRMED BY OPERATOR" else "SPEC CONFIRMATION REQUIRED",
            "Still request" to "6000 x 8000\n8000 x 6000 if the first size is rejected",
            "Capture mode" to "Maximum-resolution sensor mode\nJPEG quality $JPEG_QUALITY",
            "Timer" to "Starts at the button tap. Autofocus is part of the capture and is not done beforehand.",
            "Storage" to outputDir().absolutePath,
        )
        if (cameraError.isNotBlank()) cameraRows.add("Camera error" to cameraError)
        fillRows(binding.podCameraRows, cameraRows)
        val latest = PodSessionHolder.records.lastOrNull()
        val lastRows = if (latest == null) {
            listOf("Status" to "NOT TESTED")
        } else {
            val timing = if (latest.durationMs != null && latest.status == "SAVED") {
                val mark = if (latest.durationMs <= PodCameraRules.TARGET_MS) "PASS" else "FAIL"
                "${PodCameraRules.formatMs(latest.durationMs)} ms\n${"%.3f".format(latest.durationMs / 1000.0)} s\n$mark against 3000 ms"
            } else {
                "FAILED\n${latest.error}"
            }
            val dimensions = if (latest.width != null && latest.height != null) {
                "${latest.width} x ${latest.height}\n${PodCameraRules.formatMp(latest.width, latest.height)} MP"
            } else {
                "NOT MEASURED"
            }
            listOf(
                "Shot" to "${latest.mode} #${latest.id}\n${latest.status}",
                "File" to latest.fileName.ifBlank { "none" },
                "JPEG" to if (latest.error.isBlank()) dimensions else "$dimensions\n${latest.error}",
                "File size" to "${latest.fileBytes ?: 0} bytes\n${PodCameraRules.formatMb(latest.fileBytes)} MB\n1 MB = 1,000,000 bytes",
                "Capture-to-saved" to timing,
            )
        }
        fillRows(binding.podLastRows, lastRows)
        val sample = PodSessionHolder.samplePath?.let { File(it) }?.takeIf { it.exists() }
        if (sample != null) {
            binding.imagePodThumb.setImageBitmap(BitmapFactory.decodeFile(sample.absolutePath, BitmapFactory.Options().apply { inSampleSize = 8 }))
        }
        val saved = PodSessionHolder.records.lastOrNull { it.status == "SAVED" && it.width != null && it.height != null }
        val assessment = PodCameraRules.assess(
            rearCameraFound = rearCameraId.isNotBlank(),
            pictureAutofocusSupported = pictureAutofocus,
            latestSaved = saved,
            specConfirmed = PodSessionHolder.specConfirmed,
            legibility = PodSessionHolder.legibility,
            records = PodSessionHolder.records.toList(),
        )
        val stats = PodCameraRules.summary(PodSessionHolder.records)
        binding.textPodOverall.text = assessment.overall
        binding.textPodOverall.setTextColor(colorFor(assessment.overall))
        binding.textPodNotes.text = buildString {
            append("The 30-capture run is automatic. It is not 30 separate button taps. ")
            append("The time is from the capture request until the JPEG is saved and readable. It does not include an fsync.")
            if (batchRemaining > 0 || captureInFlight) {
                append("\n\nIn progress. Remaining scheduled shots: $batchRemaining.")
            }
        }
        val summaryRows = mutableListOf(
            "Attempts" to stats.attempts.toString(),
            "Saved" to stats.saved.toString(),
            "Failed" to stats.failed.toString(),
            "Min" to msOrBlank(stats.minMs),
            "Mean" to msOrBlank(stats.meanMs),
            "Max" to msOrBlank(stats.maxMs),
            "P95" to msOrBlank(stats.p95Ms),
            "Within 3000 ms" to stats.within3s.toString(),
            "Over 3000 ms" to stats.over3s.toString(),
            "Average file size" to if (stats.averageBytes == null) {
                "NOT TESTED"
            } else {
                "${stats.averageBytes.roundToLong()} bytes\n${PodCameraRules.formatMb(stats.averageBytes.roundToLong())} MB"
            },
            "Legibility" to PodSessionHolder.legibility,
        )
        listOf(
            assessment.rearCamera,
            assessment.autofocus,
            assessment.jpegResolution,
            assessment.productSpec,
            assessment.legibility,
            assessment.timing,
        ).forEach { summaryRows.add(it.name to "${it.status}\n${it.detail}") }
        fillRows(binding.podSummaryRows, summaryRows)
        val busy = captureInFlight || batchRemaining > 0
        binding.buttonPodCapture.isEnabled = !busy
        binding.buttonPodBatch.isEnabled = !busy
    }

    private fun msOrBlank(value: Double?): String = if (value == null) "NOT TESTED" else "${PodCameraRules.formatMs(value)} ms"

    private fun fillRows(container: android.widget.LinearLayout, rows: List<Pair<String, String>>) {
        container.removeAllViews()
        val labelColor = getColor(R.color.muted)
        val valueColor = getColor(R.color.ink)
        rows.forEach { (label, value) ->
            container.addView(android.widget.TextView(this).apply {
                text = label
                setTextColor(labelColor)
                textSize = 13f
                setPadding(0, dp(14), 0, dp(2))
            })
            container.addView(android.widget.TextView(this).apply {
                text = value
                setTextColor(valueColor)
                textSize = 18f
                setTextIsSelectable(true)
                setLineSpacing(dp(2).toFloat(), 1f)
            })
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun colorFor(status: String): Int {
        val color = when (status) {
            "PASS" -> R.color.pass_green
            "FAIL" -> R.color.fail_red
            else -> R.color.not_verified_amber
        }
        return getColor(color)
    }

    private fun viewSample() {
        val file = sampleFile() ?: return
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, "image/jpeg").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
    }

    private fun shareSample() {
        val file = sampleFile() ?: return
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        startActivity(
            Intent(Intent.ACTION_SEND)
                .setType("image/jpeg")
                .putExtra(Intent.EXTRA_STREAM, uri)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION),
        )
    }

    private fun sampleFile(): File? {
        val path = PodSessionHolder.samplePath
        val file = if (path != null) File(path) else null
        if (file == null || !file.exists()) {
            Toast.makeText(this, "Capture a manual sample first.", Toast.LENGTH_SHORT).show()
            return null
        }
        return file
    }

    private fun outputDir(): File {
        val base = getExternalFilesDir(Environment.DIRECTORY_PICTURES) ?: filesDir
        return File(base, "pod-camera").apply { mkdirs() }
    }

    private fun sessionFile(): File = File(filesDir, "pod-camera-session.json")

    private fun writeExport(uri: android.net.Uri, text: String) {
        Thread {
            runCatching {
                contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray(Charsets.UTF_8)) }
                    ?: error("Could not open the export destination.")
            }.onSuccess {
                mainHandler.post { Toast.makeText(this, "Export saved.", Toast.LENGTH_SHORT).show() }
            }.onFailure { error ->
                mainHandler.post { Toast.makeText(this, error.message, Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    private fun buildCsv(): String {
        val headers = listOf(
            "id", "mode", "started_at_iso", "ended_at_iso", "t0_elapsed_realtime_nanos", "t1_elapsed_realtime_nanos",
            "duration_ms", "status", "error", "file_name", "file_bytes", "width_px", "height_px", "megapixels",
            "file_mb_decimal", "within_3000_ms", "legibility",
        )
        val rows = PodSessionHolder.records.map { record ->
            listOf(
                record.id.toString(),
                record.mode,
                record.startedAt,
                record.endedAt,
                record.t0Nanos.toString(),
                record.t1Nanos?.toString().orEmpty(),
                PodCameraRules.formatMs(record.durationMs),
                record.status,
                record.error,
                record.fileName,
                record.fileBytes?.toString().orEmpty(),
                record.width?.toString().orEmpty(),
                record.height?.toString().orEmpty(),
                if (record.width != null && record.height != null) PodCameraRules.formatMp(record.width, record.height) else "",
                PodCameraRules.formatMb(record.fileBytes),
                if (record.status == "SAVED" && record.durationMs != null && record.durationMs <= PodCameraRules.TARGET_MS) "true" else "false",
                if (record.mode == "manual") PodSessionHolder.legibility else "NOT REVIEWED",
            )
        }
        return PodCameraRules.toCsv(headers, rows)
    }

    private fun buildJson(): String {
        val size = selectedSize
        val saved = PodSessionHolder.records.lastOrNull { it.status == "SAVED" }
        val assessment = PodCameraRules.assess(
            rearCameraFound = rearCameraId.isNotBlank(),
            pictureAutofocusSupported = pictureAutofocus,
            latestSaved = saved,
            specConfirmed = PodSessionHolder.specConfirmed,
            legibility = PodSessionHolder.legibility,
            records = PodSessionHolder.records.toList(),
        )
        val stats = PodCameraRules.summary(PodSessionHolder.records)
        val root = JSONObject()
            .put("exported_at", Instant.now().toString())
            .put("manufacturer", android.os.Build.MANUFACTURER)
            .put("model", android.os.Build.MODEL)
            .put("android_release", android.os.Build.VERSION.RELEASE)
            .put("build_fingerprint", android.os.Build.FINGERPRINT)
            .put("app_version", appVersion())
            .put("camera_id", rearCameraId)
            .put("hardware_level", hardwareLevel)
            .put("af_modes", JSONArray(afModes))
            .put("picture_autofocus_supported", pictureAutofocus)
            .put("sensor_pixel_array", sensorArray)
            .put("selected_jpeg_width", size?.width ?: JSONObject.NULL)
            .put("selected_jpeg_height", size?.height ?: JSONObject.NULL)
            .put("jpeg_quality", JPEG_QUALITY)
            .put("capture_mode", "CameraX CAPTURE_MODE_MAXIMIZE_QUALITY")
            .put("timing_definition", "elapsedRealtimeNanos from the capture request to onImageSaved plus a nonzero readable JPEG. Application-level callback timing, not fsync.")
            .put("storage", "app-specific files")
            .put("megabyte_definition", "1 MB = 1,000,000 bytes")
            .put("spec_confirmed", PodSessionHolder.specConfirmed)
            .put("spec_confirmed_at", PodSessionHolder.specConfirmedAt ?: JSONObject.NULL)
            .put("legibility", PodSessionHolder.legibility)
            .put("overall", assessment.overall)
            .put("summary", JSONObject()
                .put("attempts", stats.attempts)
                .put("saved", stats.saved)
                .put("failed", stats.failed)
                .put("min_ms", stats.minMs ?: JSONObject.NULL)
                .put("mean_ms", stats.meanMs ?: JSONObject.NULL)
                .put("max_ms", stats.maxMs ?: JSONObject.NULL)
                .put("p95_ms", stats.p95Ms ?: JSONObject.NULL)
                .put("within_3000_ms", stats.within3s)
                .put("over_3000_ms", stats.over3s)
                .put("average_bytes", stats.averageBytes ?: JSONObject.NULL))
        val attempts = JSONArray()
        PodSessionHolder.records.forEach { record ->
            attempts.put(JSONObject()
                .put("id", record.id)
                .put("mode", record.mode)
                .put("started_at", record.startedAt)
                .put("ended_at", record.endedAt)
                .put("t0_nanos", record.t0Nanos)
                .put("t1_nanos", record.t1Nanos ?: JSONObject.NULL)
                .put("duration_ms", record.durationMs ?: JSONObject.NULL)
                .put("status", record.status)
                .put("error", record.error)
                .put("file_name", record.fileName)
                .put("file_bytes", record.fileBytes ?: JSONObject.NULL)
                .put("width", record.width ?: JSONObject.NULL)
                .put("height", record.height ?: JSONObject.NULL))
        }
        root.put("attempts", attempts)
        return root.toString(2)
    }

    private fun appVersion(): String = runCatching {
        packageManager.getPackageInfo(packageName, 0).versionName
    }.getOrNull() ?: "unknown"

    private fun hardwareName(level: Int?): String = when (level) {
        CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY -> "LEGACY"
        CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED -> "LIMITED"
        CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_FULL -> "FULL"
        CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_3 -> "LEVEL_3"
        CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL -> "EXTERNAL"
        else -> "NOT REPORTED"
    }

    private fun afName(mode: Int): String = when (mode) {
        CameraMetadata.CONTROL_AF_MODE_OFF -> "OFF"
        CameraMetadata.CONTROL_AF_MODE_AUTO -> "AUTO"
        CameraMetadata.CONTROL_AF_MODE_MACRO -> "MACRO"
        CameraMetadata.CONTROL_AF_MODE_CONTINUOUS_VIDEO -> "CONTINUOUS_VIDEO"
        CameraMetadata.CONTROL_AF_MODE_CONTINUOUS_PICTURE -> "CONTINUOUS_PICTURE"
        CameraMetadata.CONTROL_AF_MODE_EDOF -> "EDOF"
        else -> "UNKNOWN_$mode"
    }

    companion object {
        private const val JPEG_QUALITY = 95
        private const val BATCH_COUNT = 30
        private const val TIMEOUT_MS = 45_000L
        private val TRIAL_SIZES = listOf(Size(6000, 8000), Size(8000, 6000))
    }
}

private object PodSessionHolder {
    var restored = false
    val records = mutableListOf<CaptureRecord>()
    var legibility: String = "NOT REVIEWED"
    var specConfirmed: Boolean = false
    var specConfirmedAt: String? = null
    var samplePath: String? = null
    var batchCancel: Boolean = false

    fun restore(file: File) {
        if (restored) return
        restored = true
        if (!file.exists()) return
        runCatching {
            val root = JSONObject(file.readText())
            legibility = root.optString("legibility", "NOT REVIEWED")
            specConfirmed = root.optBoolean("spec_confirmed", false)
            specConfirmedAt = root.nullableString("spec_confirmed_at")
            samplePath = root.nullableString("sample_path")
            records.clear()
            val attempts = root.optJSONArray("attempts") ?: JSONArray()
            for (index in 0 until attempts.length()) {
                val item = attempts.getJSONObject(index)
                records.add(
                    CaptureRecord(
                        id = item.getInt("id"),
                        mode = item.getString("mode"),
                        startedAt = item.optString("started_at"),
                        endedAt = item.optString("ended_at"),
                        t0Nanos = item.optLong("t0_nanos"),
                        t1Nanos = item.nullableLong("t1_nanos"),
                        durationMs = item.nullableDouble("duration_ms"),
                        status = item.optString("status"),
                        error = item.optString("error"),
                        fileName = item.optString("file_name"),
                        fileBytes = item.nullableLong("file_bytes"),
                        width = item.nullableInt("width"),
                        height = item.nullableInt("height"),
                    ),
                )
            }
        }
    }

    fun persist(file: File) {
        val attempts = JSONArray()
        records.forEach { record ->
            attempts.put(JSONObject()
                .put("id", record.id)
                .put("mode", record.mode)
                .put("started_at", record.startedAt)
                .put("ended_at", record.endedAt)
                .put("t0_nanos", record.t0Nanos)
                .put("t1_nanos", record.t1Nanos ?: JSONObject.NULL)
                .put("duration_ms", record.durationMs ?: JSONObject.NULL)
                .put("status", record.status)
                .put("error", record.error)
                .put("file_name", record.fileName)
                .put("file_bytes", record.fileBytes ?: JSONObject.NULL)
                .put("width", record.width ?: JSONObject.NULL)
                .put("height", record.height ?: JSONObject.NULL))
        }
        val root = JSONObject()
            .put("legibility", legibility)
            .put("spec_confirmed", specConfirmed)
            .put("spec_confirmed_at", specConfirmedAt ?: JSONObject.NULL)
            .put("sample_path", samplePath ?: JSONObject.NULL)
            .put("attempts", attempts)
        file.writeText(root.toString())
    }
}

private fun JSONObject.nullableString(key: String): String? {
    if (!has(key) || isNull(key)) return null
    return optString(key).ifBlank { null }
}

private fun JSONObject.nullableLong(key: String): Long? {
    if (!has(key) || isNull(key)) return null
    return getLong(key)
}

private fun JSONObject.nullableDouble(key: String): Double? {
    if (!has(key) || isNull(key)) return null
    return getDouble(key)
}

private fun JSONObject.nullableInt(key: String): Int? {
    if (!has(key) || isNull(key)) return null
    return getInt(key)
}

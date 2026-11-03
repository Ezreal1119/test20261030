package com.patrick.test20261030

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.os.Bundle
import android.os.SystemClock
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.android.gms.tasks.Tasks
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.face.FaceDetection
import com.google.mlkit.vision.face.FaceDetector
import com.google.mlkit.vision.face.FaceDetectorOptions
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.TextRecognizer
import com.google.mlkit.vision.text.chinese.ChineseTextRecognizerOptions
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import com.patrick.test20261030.databinding.ActivityOnDeviceAiBinding
import java.io.File
import java.util.concurrent.Executors

class OnDeviceAiActivity : AppCompatActivity() {
    private lateinit var binding: ActivityOnDeviceAiBinding
    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private var imageCapture: ImageCapture? = null
    private val faceDetector: FaceDetector = FaceDetection.getClient(
        FaceDetectorOptions.Builder()
            .setPerformanceMode(FaceDetectorOptions.PERFORMANCE_MODE_ACCURATE)
            .setMinFaceSize(0.08f)
            .build(),
    )
    private val latinRecognizer: TextRecognizer = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)
    private val chineseRecognizer: TextRecognizer = TextRecognition.getClient(
        ChineseTextRecognizerOptions.Builder().build(),
    )

    private val requestCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) {
            startCamera()
        } else {
            binding.textResult.text = "Camera permission is required to capture a photo on this device."
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityOnDeviceAiBinding.inflate(layoutInflater)
        setContentView(binding.root)
        enableEdgeToEdge()
        ViewCompat.setOnApplyWindowInsetsListener(binding.aiRoot) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        binding.buttonCapture.setOnClickListener { capture() }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            requestCamera.launch(Manifest.permission.CAMERA)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
        faceDetector.close()
        latinRecognizer.close()
        chineseRecognizer.close()
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val preview = Preview.Builder().build().also {
                it.surfaceProvider = binding.preview.surfaceProvider
            }
            val capture = ImageCapture.Builder().build()
            imageCapture = capture
            provider.unbindAll()
            provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, capture)
        }, ContextCompat.getMainExecutor(this))
    }

    private fun capture() {
        val capture = imageCapture
        if (capture == null) {
            binding.textResult.text = "Camera is not ready."
            return
        }
        binding.buttonCapture.isEnabled = false
        binding.textResult.text = "Checking for privacy content on this device..."
        val file = File(cacheDir, "on-device-capture.jpg")
        val options = ImageCapture.OutputFileOptions.Builder(file).build()
        capture.takePicture(
            options,
            cameraExecutor,
            object : ImageCapture.OnImageSavedCallback {
                override fun onImageSaved(outputFileResults: ImageCapture.OutputFileResults) {
                    val report = runCatching { assess(file) }.getOrElse { error ->
                        "Assessment failed.\n${error.message ?: error.javaClass.simpleName}"
                    }
                    runOnUiThread {
                        binding.textResult.text = report
                        binding.buttonCapture.isEnabled = true
                    }
                }

                override fun onError(exception: ImageCaptureException) {
                    runOnUiThread {
                        binding.textResult.text = "Capture failed.\n${exception.message}"
                        binding.buttonCapture.isEnabled = true
                    }
                }
            },
        )
    }

    private fun assess(file: File): String {
        val bitmap = decodeUpright(file)
        val image = InputImage.fromBitmap(bitmap, 0)
        val faceStart = SystemClock.elapsedRealtimeNanos()
        val faces = Tasks.await(faceDetector.process(image))
        val faceMs = elapsedMs(faceStart)
        val latinStart = SystemClock.elapsedRealtimeNanos()
        val latin = Tasks.await(latinRecognizer.process(image)).text
        val latinMs = elapsedMs(latinStart)
        val chineseStart = SystemClock.elapsedRealtimeNanos()
        val chinese = Tasks.await(chineseRecognizer.process(image)).text
        val chineseMs = elapsedMs(chineseStart)
        bitmap.recycle()

        val findings = linkedMapOf<String, String>()
        if (faces.isNotEmpty()) {
            findings["Face"] = "Face: ${faces.size} detected"
        }
        findingsFromText("$latin\n$chinese").forEach { finding ->
            findings.putIfAbsent(finding.label, "${finding.label}: ${finding.detail}")
        }
        val detected = findings.isNotEmpty()

        return buildString {
            appendLine(if (detected) "Privacy content: DETECTED" else "Privacy content: NOT DETECTED")
            appendLine()
            appendLine("Labels:")
            if (findings.isEmpty()) {
                appendLine("- none")
            } else {
                findings.values.forEach { appendLine("- $it") }
            }
            appendLine()
            appendLine("Inference: COMPLETE")
            appendLine("Models:")
            appendLine("- ML Kit face detection $FACE_VERSION, bundled")
            appendLine("- ML Kit Latin text recognition $TEXT_VERSION, bundled")
            appendLine("- ML Kit Chinese text recognition $TEXT_VERSION, bundled")
            appendLine("Where: on this device. This page does not upload the image.")
            appendLine("CPU or Hexagon: not reported by these APIs.")
            appendLine("Face time: $faceMs ms")
            appendLine("Latin text time: $latinMs ms")
            appendLine("Chinese text time: $chineseMs ms")
            appendLine()
            appendLine("Compliance: ${if (detected) "FAIL" else "PASS"}")
            append(
                if (detected) {
                    "A face, phone number, email, identity number, payment card, license plate, or street address was found. Values are masked. This is a reference check, not the customer's proof-of-delivery policy."
                } else {
                    "No face, phone number, email, identity number, payment card, license plate, or street address was found. This is a reference check, not the customer's proof-of-delivery policy."
                },
            )
        }
    }

    private fun elapsedMs(started: Long): String =
        "%.1f".format((SystemClock.elapsedRealtimeNanos() - started) / 1_000_000.0)

    private fun findingsFromText(text: String): List<Finding> {
        val collapsed = text.replace(DIGIT_SEPARATOR, "")
        val found = linkedMapOf<String, Finding>()
        fun add(label: String, raw: String) {
            val key = label + "|" + raw.filter { !it.isWhitespace() }.lowercase()
            found.putIfAbsent(key, Finding(label, mask(raw)))
        }
        listOf(text, collapsed).forEach { source ->
            PHONE.findAll(source).forEach { add("Phone number", it.value) }
            EMAIL.findAll(source).forEach { add("Email address", it.value) }
            IDENTITY.findAll(source).forEach { add("Identity number", it.value) }
            PLATE.findAll(source).forEach { add("License plate", it.value) }
            CN_ADDRESS.findAll(source).forEach { add("Street address", it.value) }
            EN_ADDRESS.findAll(source).forEach { add("Street address", it.value) }
            CARD.findAll(source).forEach { match ->
                val digits = match.value.filter { it.isDigit() }
                if (digits.length in 13..19 && !IDENTITY.matches(digits) && luhn(digits)) {
                    add("Payment card", digits)
                }
            }
        }
        return found.values.toList()
    }

    private fun mask(value: String): String {
        val compact = value.filter { !it.isWhitespace() }
        if (compact.length <= 4) return "****"
        return compact.take(2) + "****" + compact.takeLast(2)
    }

    private fun luhn(digits: String): Boolean {
        var sum = 0
        digits.reversed().forEachIndexed { index, character ->
            var number = character.digitToInt()
            if (index % 2 == 1) {
                number *= 2
                if (number > 9) number -= 9
            }
            sum += number
        }
        return sum % 10 == 0
    }

    private fun decodeUpright(file: File): Bitmap {
        val source = BitmapFactory.decodeFile(file.absolutePath)
            ?: error("Could not read the captured photo.")
        val degrees = when (
            ExifInterface(file.absolutePath).getAttributeInt(
                ExifInterface.TAG_ORIENTATION,
                ExifInterface.ORIENTATION_NORMAL,
            )
        ) {
            ExifInterface.ORIENTATION_ROTATE_90 -> 90
            ExifInterface.ORIENTATION_ROTATE_180 -> 180
            ExifInterface.ORIENTATION_ROTATE_270 -> 270
            else -> 0
        }
        val rotated = if (degrees == 0) {
            source
        } else {
            val matrix = Matrix().apply { postRotate(degrees.toFloat()) }
            Bitmap.createBitmap(source, 0, 0, source.width, source.height, matrix, true).also {
                if (it != source) source.recycle()
            }
        }
        val longEdge = maxOf(rotated.width, rotated.height)
        if (longEdge <= MAX_EDGE) return rotated
        val scale = MAX_EDGE.toFloat() / longEdge
        val width = (rotated.width * scale).toInt().coerceAtLeast(1)
        val height = (rotated.height * scale).toInt().coerceAtLeast(1)
        return Bitmap.createScaledBitmap(rotated, width, height, true).also {
            if (it != rotated) rotated.recycle()
        }
    }

    private data class Finding(val label: String, val detail: String)

    companion object {
        private const val FACE_VERSION = "16.1.7"
        private const val TEXT_VERSION = "16.0.1"
        private const val MAX_EDGE = 1600
        private val DIGIT_SEPARATOR = Regex("""(?<=\d)[\s-]+(?=\d)""")
        private val PHONE = Regex("""(?<!\d)(?:\+?86[\s-]?)?1[3-9]\d{9}(?!\d)""")
        private val EMAIL = Regex("""[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}""")
        private val IDENTITY = Regex("""(?<!\d)\d{17}[\dXx](?!\d)""")
        private val CARD = Regex("""(?<!\d)(?:\d[ -]?){13,19}(?!\d)""")
        private val PLATE = Regex("""[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼][A-Z][A-Z0-9]{5,6}""")
        private val CN_ADDRESS = Regex("""[\u4e00-\u9fff]{2,}(?:省|市|区|县|路|街|道|号|栋|单元|室)""")
        private val EN_ADDRESS = Regex(
            """(?i)\d{1,5}\s+[A-Za-z0-9.'\- ]{2,40}\s(?:Street|St|Road|Rd|Avenue|Ave|Lane|Drive|Dr)\b""",
        )
    }
}

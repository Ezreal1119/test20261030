package com.patrick.test20261030

import kotlin.math.ceil

data class CaptureRecord(
    val id: Int,
    val mode: String,
    val startedAt: String,
    val endedAt: String,
    val t0Nanos: Long,
    val t1Nanos: Long?,
    val durationMs: Double?,
    val status: String,
    val error: String,
    val fileName: String,
    val fileBytes: Long?,
    val width: Int?,
    val height: Int?,
)

data class GateResult(val name: String, val status: String, val detail: String)

data class TimingSummary(
    val attempts: Int,
    val saved: Int,
    val failed: Int,
    val minMs: Double?,
    val meanMs: Double?,
    val maxMs: Double?,
    val p95Ms: Double?,
    val within3s: Int,
    val over3s: Int,
    val averageBytes: Double?,
)

data class PodAssessment(
    val rearCamera: GateResult,
    val autofocus: GateResult,
    val jpegResolution: GateResult,
    val productSpec: GateResult,
    val legibility: GateResult,
    val timing: GateResult,
    val overall: String,
)

object PodCameraRules {
    const val TARGET_MS = 3000.0
    const val MIN_PIXELS = 13_000_000L
    const val MB = 1_000_000.0

    fun pixels(width: Int, height: Int): Long = width.toLong() * height.toLong()

    fun megapixels(width: Int, height: Int): Double = pixels(width, height) / 1_000_000.0

    fun megabytes(bytes: Long): Double = bytes / MB

    fun chooseJpegSize(sizes: List<Pair<Int, Int>>): Pair<Int, Int>? {
        val ranked = sizes.sortedByDescending { pixels(it.first, it.second) }
        return ranked.firstOrNull { pixels(it.first, it.second) >= MIN_PIXELS } ?: ranked.firstOrNull()
    }

    fun summary(records: List<CaptureRecord>): TimingSummary {
        val durations = records.mapNotNull { it.durationMs }
        val saved = records.filter { it.status == "SAVED" }
        val savedBytes = saved.mapNotNull { it.fileBytes }
        return TimingSummary(
            attempts = records.size,
            saved = saved.size,
            failed = records.count { it.status != "SAVED" },
            minMs = durations.minOrNull(),
            meanMs = if (durations.isEmpty()) null else durations.average(),
            maxMs = durations.maxOrNull(),
            p95Ms = percentileNearestRank(durations, 0.95),
            within3s = records.count { it.status == "SAVED" && it.durationMs != null && it.durationMs <= TARGET_MS },
            over3s = records.count { it.durationMs != null && it.durationMs > TARGET_MS },
            averageBytes = if (savedBytes.isEmpty()) null else savedBytes.average(),
        )
    }

    fun assess(
        rearCameraFound: Boolean,
        pictureAutofocusSupported: Boolean,
        latestSaved: CaptureRecord?,
        specConfirmed: Boolean,
        legibility: String,
        records: List<CaptureRecord>,
    ): PodAssessment {
        val rear = if (rearCameraFound) {
            GateResult("Rear camera", "PASS", "A rear-facing camera was found on this device.")
        } else {
            GateResult("Rear camera", "FAIL", "No rear-facing camera was found.")
        }
        val autofocus = when {
            !rearCameraFound -> GateResult("Autofocus", "NOT VERIFIED", "Autofocus was not queried because no rear camera was found.")
            pictureAutofocusSupported -> GateResult(
                "Autofocus",
                "PASS",
                "The camera reports AUTO, MACRO, or CONTINUOUS_PICTURE. This is capability evidence, not a measured focus on a label.",
            )
            else -> GateResult(
                "Autofocus",
                "FAIL",
                "The rear camera does not report a still-picture autofocus mode.",
            )
        }
        val jpeg = when {
            latestSaved == null || latestSaved.width == null || latestSaved.height == null -> GateResult(
                "Capture resolution",
                "NOT TESTED",
                "No saved JPEG has been measured yet.",
            )
            pixels(latestSaved.width, latestSaved.height) >= MIN_PIXELS -> GateResult(
                "Capture resolution",
                "PASS",
                "Latest saved JPEG is ${latestSaved.width} x ${latestSaved.height} (${formatMp(latestSaved.width, latestSaved.height)} MP).",
            )
            else -> GateResult(
                "Capture resolution",
                "FAIL",
                "Latest saved JPEG is ${latestSaved.width} x ${latestSaved.height}, under 13,000,000 pixels.",
            )
        }
        val spec = if (specConfirmed) {
            GateResult(
                "Product specification",
                "PASS",
                "Operator confirmed an authoritative specification states the rear camera is at least 13 MP. This app did not read that document.",
            )
        } else {
            GateResult(
                "Product specification",
                "NOT VERIFIED",
                "SPEC CONFIRMATION REQUIRED. JPEG dimensions are not the sensor specification.",
            )
        }
        val legibilityGate = when (legibility) {
            "PASS" -> GateResult("Legibility", "PASS", "Operator reviewed the sample image and marked the label legible.")
            "FAIL" -> GateResult("Legibility", "FAIL", "Operator reviewed the sample image and marked it not legible.")
            else -> GateResult(
                "Legibility",
                "NOT VERIFIED",
                "NOT REVIEWED. Resolution alone does not prove the address, tracking number, and barcode are legible.",
            )
        }
        val timing = timingGate(records)
        val gates = listOf(rear, autofocus, jpeg, spec, legibilityGate, timing)
        val overall = when {
            gates.any { it.status == "FAIL" } -> "FAIL"
            gates.all { it.status == "PASS" } -> "PASS"
            else -> "NOT VERIFIED"
        }
        return PodAssessment(rear, autofocus, jpeg, spec, legibilityGate, timing, overall)
    }

    fun timingGate(records: List<CaptureRecord>): GateResult {
        if (records.isEmpty()) {
            return GateResult("Capture-to-saved time", "NOT TESTED", "No capture has been measured.")
        }
        val slow = records.filter { it.durationMs == null || it.durationMs > TARGET_MS || it.status != "SAVED" }
        return if (slow.isEmpty()) {
            GateResult(
                "Capture-to-saved time",
                "PASS",
                "All ${records.size} measured captures saved successfully and each was <= 3000 ms.",
            )
        } else {
            GateResult(
                "Capture-to-saved time",
                "FAIL",
                "${slow.size} of ${records.size} captures failed or exceeded 3000 ms. The average is not the pass rule.",
            )
        }
    }

    fun percentileNearestRank(values: List<Double>, fraction: Double): Double? {
        if (values.isEmpty()) return null
        val sorted = values.sorted()
        val rank = ceil(fraction * sorted.size).toInt().coerceAtLeast(1)
        return sorted[rank - 1]
    }

    fun csvField(value: String): String {
        val escaped = value.replace("\"", "\"\"")
        return if (escaped.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) "\"$escaped\"" else escaped
    }

    fun toCsv(headers: List<String>, rows: List<List<String>>): String {
        val lines = ArrayList<String>(rows.size + 1)
        lines.add(headers.joinToString(",") { csvField(it) })
        rows.forEach { row -> lines.add(row.joinToString(",") { csvField(it) }) }
        return lines.joinToString("\n")
    }

    fun formatMp(width: Int, height: Int): String = "%.2f".format(megapixels(width, height))

    fun formatMs(value: Double?): String = if (value == null) "" else "%.1f".format(value)

    fun formatMb(bytes: Long?): String = if (bytes == null) "" else "%.2f".format(megabytes(bytes))
}

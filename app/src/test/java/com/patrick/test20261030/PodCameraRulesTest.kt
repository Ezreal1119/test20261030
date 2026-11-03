package com.patrick.test20261030

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PodCameraRulesTest {
    @Test
    fun choosesAtLeast13MegapixelsWhenAvailable() {
        val chosen = PodCameraRules.chooseJpegSize(listOf(4000 to 3000, 8000 to 6000, 1920 to 1080))
        assertEquals(8000 to 6000, chosen)
    }

    @Test
    fun reportsLargestSizeWhenNoneReach13Megapixels() {
        val chosen = PodCameraRules.chooseJpegSize(listOf(1920 to 1080, 4000 to 3000))
        assertEquals(4000 to 3000, chosen)
        assertTrue(PodCameraRules.pixels(4000, 3000) < PodCameraRules.MIN_PIXELS)
    }

    @Test
    fun overallStaysNotVerifiedUntilEveryGatePasses() {
        val saved = record(status = "SAVED", durationMs = 900.0, width = 8000, height = 6000)
        val assessment = PodCameraRules.assess(
            rearCameraFound = true,
            pictureAutofocusSupported = true,
            latestSaved = saved,
            specConfirmed = false,
            legibility = "NOT REVIEWED",
            records = listOf(saved),
        )
        assertEquals("PASS", assessment.rearCamera.status)
        assertEquals("PASS", assessment.jpegResolution.status)
        assertEquals("NOT VERIFIED", assessment.productSpec.status)
        assertEquals("NOT VERIFIED", assessment.legibility.status)
        assertEquals("NOT VERIFIED", assessment.overall)
    }

    @Test
    fun oneSlowCaptureFailsEvenWhenTheAverageWouldPass() {
        val records = listOf(
            record(status = "SAVED", durationMs = 100.0, width = 8000, height = 6000),
            record(id = 2, status = "SAVED", durationMs = 3000.1, width = 8000, height = 6000),
        )
        val assessment = PodCameraRules.assess(
            rearCameraFound = true,
            pictureAutofocusSupported = true,
            latestSaved = records.last(),
            specConfirmed = true,
            legibility = "PASS",
            records = records,
        )
        assertEquals("FAIL", assessment.timing.status)
        assertEquals("FAIL", assessment.overall)
    }

    @Test
    fun allGatesPassOnlyWhenEvidenceIsComplete() {
        val saved = record(status = "SAVED", durationMs = 3000.0, width = 8000, height = 6000)
        val assessment = PodCameraRules.assess(
            rearCameraFound = true,
            pictureAutofocusSupported = true,
            latestSaved = saved,
            specConfirmed = true,
            legibility = "PASS",
            records = listOf(saved),
        )
        assertEquals("PASS", assessment.overall)
    }

    @Test
    fun p95UsesNearestRank() {
        val values = (1..100).map { it.toDouble() }
        assertEquals(95.0, PodCameraRules.percentileNearestRank(values, 0.95)!!, 0.0)
    }

    @Test
    fun csvQuotesCommasAndQuotes() {
        val csv = PodCameraRules.toCsv(
            listOf("error", "file"),
            listOf(listOf("camera failed, retry", "label \"a\".jpg")),
        )
        assertEquals("error,file\n\"camera failed, retry\",\"label \"\"a\"\".jpg\"", csv)
    }

    private fun record(
        id: Int = 1,
        status: String,
        durationMs: Double?,
        width: Int?,
        height: Int?,
    ) = CaptureRecord(
        id = id,
        mode = "manual",
        startedAt = "2026-11-02T00:00:00Z",
        endedAt = "2026-11-02T00:00:01Z",
        t0Nanos = 0L,
        t1Nanos = 1L,
        durationMs = durationMs,
        status = status,
        error = "",
        fileName = "sample.jpg",
        fileBytes = 2_500_000L,
        width = width,
        height = height,
    )
}

package com.patrick.test20261030

data class TimingSegments(
    val totalMs: Long,
    val deviceMs: Long,
    val webauthnMs: Long,
    val sessionMs: Long,
)

object Timing {
    const val TARGET_MS = 20_000L

    fun segments(startNs: Long, deviceEndNs: Long, webauthnEndNs: Long, finishNs: Long): TimingSegments {
        require(deviceEndNs >= startNs && webauthnEndNs >= deviceEndNs && finishNs >= webauthnEndNs) {
            "Timer boundaries are out of order"
        }
        val totalMs = (finishNs - startNs) / 1_000_000L
        val deviceMs = (deviceEndNs - startNs) / 1_000_000L
        val webauthnMs = (webauthnEndNs - deviceEndNs) / 1_000_000L
        val sessionMs = totalMs - deviceMs - webauthnMs
        check(sessionMs >= 0L) { "Session segment is negative" }
        return TimingSegments(totalMs, deviceMs, webauthnMs, sessionMs)
    }
}

package com.patrick.test20261030

import android.os.Bundle
import android.os.SystemClock
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.doOnPreDraw
import androidx.lifecycle.lifecycleScope
import com.patrick.test20261030.databinding.ActivityAuthenticatedHomeBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class AuthenticatedHomeActivity : AppCompatActivity() {
    private lateinit var binding: ActivityAuthenticatedHomeBinding
    private var recorded = false
    private var timing: TimingSegments? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAuthenticatedHomeBinding.inflate(layoutInflater)
        setContentView(binding.root)
        enableEdgeToEdge()
        ViewCompat.setOnApplyWindowInsetsListener(binding.homeRoot) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        val sessionToken = intent.getStringExtra(EXTRA_SESSION_TOKEN).orEmpty()
        if (sessionToken.isBlank() || intent.getStringExtra(EXTRA_TRANSACTION_ID).isNullOrBlank()) {
            finish()
            return
        }
        recorded = savedInstanceState?.getBoolean(STATE_RECORDED) ?: false
        if (recorded) {
            showSaved(savedInstanceState)
        } else {
            binding.textHomeDetails.text = "Session confirmed. Finalizing the sign-on measurement."
            binding.homeRoot.doOnPreDraw {
                if (!recorded) {
                    recorded = true
                    finishMeasurement()
                }
            }
        }
        binding.buttonRetryReport.setOnClickListener { timing?.let { saveAttempt(it) } }
        binding.buttonSignOut.setOnClickListener { signOut(sessionToken) }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_RECORDED, recorded)
        timing?.let { segments ->
            outState.putLong(STATE_TOTAL, segments.totalMs)
            outState.putLong(STATE_DEVICE, segments.deviceMs)
            outState.putLong(STATE_WEB, segments.webauthnMs)
            outState.putLong(STATE_SESSION, segments.sessionMs)
        }
    }

    private fun finishMeasurement() {
        val start = intent.getLongExtra(EXTRA_START_NS, 0L)
        val deviceEnd = intent.getLongExtra(EXTRA_DEVICE_END_NS, 0L)
        val webEnd = intent.getLongExtra(EXTRA_WEBAUTHN_END_NS, 0L)
        val finish = SystemClock.elapsedRealtimeNanos()
        val segments = try {
            Timing.segments(start, deviceEnd, webEnd, finish)
        } catch (error: Exception) {
            binding.textHomeBanner.text = "FAIL"
            binding.textHomeBanner.setTextColor(0xFFA12622.toInt())
            binding.textHomeDetails.text = error.message
            return
        }
        timing = segments
        render(segments, "Saving the measured attempt.")
        saveAttempt(segments)
    }

    private fun saveAttempt(segments: TimingSegments) {
        val prefs = AppPreferences(this)
        lifecycleScope.launch {
            try {
                val body = JSONObject()
                    .put("transaction_id", intent.getStringExtra(EXTRA_TRANSACTION_ID))
                    .put("registration_id", intent.getStringExtra(EXTRA_REGISTRATION_ID))
                    .put("total_ms", segments.totalMs)
                    .put("device_ms", segments.deviceMs)
                    .put("webauthn_ms", segments.webauthnMs)
                    .put("session_ms", segments.sessionMs)
                    .put("device_result", "PASS")
                    .put("webauthn_result", "PASS")
                    .put("session_result", "PASS")
                    .put("network_type", intent.getStringExtra(EXTRA_NETWORK) ?: DeviceFacts.networkType(this@AuthenticatedHomeActivity))
                    .put("failure_reason", "")
                    .put("device_info", DeviceFacts.json(this@AuthenticatedHomeActivity))
                withContext(Dispatchers.IO) {
                    ApiClient(prefs.requireHttpsBaseUrl(), prefs.adminToken).recordAttempt(body)
                }
                binding.buttonRetryReport.visibility = android.view.View.GONE
                render(segments, "The backend stored this attempt.")
            } catch (error: Exception) {
                binding.buttonRetryReport.visibility = android.view.View.VISIBLE
                render(segments, "The measurement is shown here, but the backend did not store it: ${error.message}")
            }
        }
    }

    private fun render(segments: TimingSegments, note: String) {
        val within = segments.totalMs <= Timing.TARGET_MS
        binding.textHomeBanner.text = if (within) "PASS" else "FAIL"
        binding.textHomeBanner.setTextColor(if (within) 0xFF1B7F4E.toInt() else 0xFFA12622.toInt())
        val username = intent.getStringExtra(EXTRA_USERNAME).orEmpty()
        val registration = intent.getStringExtra(EXTRA_REGISTRATION_ID).orEmpty()
        val expires = intent.getStringExtra(EXTRA_EXPIRES).orEmpty()
        binding.textHomeDetails.text = buildString {
            appendLine("User: $username")
            appendLine("Registration ID: $registration")
            appendLine("Session expires: $expires")
            appendLine("Device authentication: ${segments.deviceMs} ms")
            appendLine("WebAuthn authentication: ${segments.webauthnMs} ms")
            appendLine("Backend/session processing: ${segments.sessionMs} ms")
            appendLine("Total authentication: ${segments.totalMs} ms")
            appendLine("Target: ${Timing.TARGET_MS} ms")
            appendLine(if (within) "Result: PASS" else "Result: FAIL")
            append(note)
        }
    }

    private fun showSaved(state: Bundle?) {
        if (state == null || !state.containsKey(STATE_TOTAL)) {
            binding.textHomeDetails.text = "This session is already measured."
            return
        }
        render(
            TimingSegments(
                state.getLong(STATE_TOTAL),
                state.getLong(STATE_DEVICE),
                state.getLong(STATE_WEB),
                state.getLong(STATE_SESSION),
            ),
            "Measurement restored after the screen was recreated.",
        )
    }

    private fun signOut(sessionToken: String) {
        val prefs = AppPreferences(this)
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    ApiClient(prefs.requireHttpsBaseUrl(), prefs.adminToken).logout(sessionToken)
                }
            } catch (error: Exception) {
                Toast.makeText(this@AuthenticatedHomeActivity, error.message, Toast.LENGTH_LONG).show()
            } finally {
                finish()
            }
        }
    }

    companion object {
        const val EXTRA_START_NS = "start_ns"
        const val EXTRA_DEVICE_END_NS = "device_end_ns"
        const val EXTRA_WEBAUTHN_END_NS = "webauthn_end_ns"
        const val EXTRA_TRANSACTION_ID = "transaction_id"
        const val EXTRA_REGISTRATION_ID = "registration_id"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_SESSION_TOKEN = "session_token"
        const val EXTRA_EXPIRES = "expires_at"
        const val EXTRA_NETWORK = "network_type"
        private const val STATE_RECORDED = "recorded"
        private const val STATE_TOTAL = "total_ms"
        private const val STATE_DEVICE = "device_ms"
        private const val STATE_WEB = "webauthn_ms"
        private const val STATE_SESSION = "session_ms"
    }
}

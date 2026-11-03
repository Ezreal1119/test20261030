package com.patrick.test20261030

import android.os.Bundle
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.patrick.test20261030.databinding.ActivityHistoryBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class HistoryActivity : AppCompatActivity() {
    private lateinit var binding: ActivityHistoryBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityHistoryBinding.inflate(layoutInflater)
        setContentView(binding.root)
        enableEdgeToEdge()
        ViewCompat.setOnApplyWindowInsetsListener(binding.historyRoot) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        binding.buttonRefreshHistory.setOnClickListener { load() }
        load()
    }

    private fun load() {
        val prefs = AppPreferences(this)
        binding.textHistory.text = "Loading history"
        lifecycleScope.launch {
            try {
                val response = withContext(Dispatchers.IO) {
                    ApiClient(prefs.requireHttpsBaseUrl(), prefs.adminToken).attempts(prefs.registrationId)
                }
                binding.textHistory.text = formatHistory(response)
            } catch (error: Exception) {
                binding.textHistory.text = "FAIL\n${error.message}"
                Toast.makeText(this@HistoryActivity, error.message, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun formatHistory(response: JSONObject): String {
        val stats = response.optJSONObject("stats")
        val attempts = response.optJSONArray("attempts")
        return buildString {
            appendLine("Timing statistics use corroborated attempts only.")
            appendLine("An average below 20 seconds is not treated as compliance by itself.")
            if (stats == null) {
                appendLine("No statistics are available.")
            } else {
                appendLine("Attempts: ${stats.optInt("count")}")
                appendLine("Successes: ${stats.optInt("successes")}")
                appendLine("Failures: ${stats.optInt("failures")}")
                appendLine("Success rate: ${stats.optString("success_rate")}")
                appendLine("Minimum: ${stats.opt("minimum_ms")}")
                appendLine("Maximum: ${stats.opt("maximum_ms")}")
                appendLine("Average: ${stats.opt("average_ms")}")
                appendLine("P95: ${stats.opt("p95_ms")}")
                appendLine("Over 20 seconds: ${stats.optInt("over_target")}")
                appendLine(stats.optString("p95_note"))
            }
            appendLine()
            if (attempts == null || attempts.length() == 0) {
                append("NOT TESTED\nNo attempts are stored.")
            } else {
                for (index in 0 until attempts.length()) {
                    val row = attempts.getJSONObject(index)
                    appendLine("Attempt ${row.optInt("attempt_number")}")
                    appendLine("  Recorded: ${row.optString("recorded_at")}")
                    appendLine("  Total: ${row.optLong("total_ms")} ms")
                    appendLine("  Device: ${row.optString("device_result")}")
                    appendLine("  WebAuthn: ${row.optString("webauthn_result")}")
                    appendLine("  Session: ${row.optString("session_result")}")
                    appendLine("  Network: ${row.optString("network_type")}")
                    appendLine("  Corroborated: ${row.optInt("corroborated") == 1}")
                    val reason = row.optString("failure_reason")
                    if (reason.isNotBlank()) {
                        appendLine("  Failure: $reason")
                    }
                    appendLine()
                }
            }
        }.trim()
    }
}

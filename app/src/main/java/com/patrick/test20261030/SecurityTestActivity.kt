package com.patrick.test20261030

import android.os.Bundle
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.patrick.test20261030.databinding.ActivitySecurityTestsBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class SecurityTestActivity : AppCompatActivity() {
    private lateinit var binding: ActivitySecurityTestsBinding
    private val keys = DeviceKeyManager()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySecurityTestsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        enableEdgeToEdge()
        ViewCompat.setOnApplyWindowInsetsListener(binding.securityRoot) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        binding.buttonDeviceChecks.setOnClickListener { runDeviceChecks() }
        binding.buttonServerSuite.setOnClickListener { runServerSuite() }
    }

    private fun runDeviceChecks() {
        val prefs = AppPreferences(this)
        setBusy(true)
        lifecycleScope.launch {
            val lines = StringBuilder("Device-side checks\n")
            try {
                if (!keys.hasKey()) {
                    lines.append("NOT TESTED\nGenerate and register a device key first.\n")
                } else if (prefs.registrationId.isBlank()) {
                    lines.append("NOT TESTED\nRegister the device first.\n")
                } else {
                    val api = ApiClient(prefs.requireHttpsBaseUrl(), prefs.adminToken)
                    lines.append(checkValid(api, prefs.registrationId))
                    lines.append(checkModified(api, prefs.registrationId))
                    lines.append(checkReplay(api, prefs.registrationId))
                    lines.append(checkUnknown(api))
                    lines.append(checkWrongKey(api, prefs.registrationId))
                    lines.append("\nExpired challenges, WebAuthn origin, RP ID, UV, and session binding are covered by the server suite.\n")
                }
            } catch (error: Exception) {
                lines.append("FAIL\n${error.message}\n")
                Toast.makeText(this@SecurityTestActivity, error.message, Toast.LENGTH_LONG).show()
            } finally {
                binding.textSecurityResults.text = lines.toString().trim()
                setBusy(false)
            }
        }
    }

    private suspend fun checkValid(api: ApiClient, registrationId: String): String {
        val challenge = withContext(Dispatchers.IO) { api.deviceChallenge(registrationId) }
        val signature = keys.sign(Base64Url.decode(challenge.getString("challenge")))
        return try {
            withContext(Dispatchers.IO) {
                api.verifyDevice(challenge.getString("challenge_id"), Base64Url.encode(signature))
            }
            "PASS  Valid device signature accepted\n"
        } catch (error: Exception) {
            "FAIL  Valid device signature was rejected: ${error.message}\n"
        }
    }

    private suspend fun checkModified(api: ApiClient, registrationId: String): String {
        val challenge = withContext(Dispatchers.IO) { api.deviceChallenge(registrationId) }
        val signature = keys.sign(Base64Url.decode(challenge.getString("challenge")))
        signature[signature.lastIndex] = (signature[signature.lastIndex].toInt() xor 0x01).toByte()
        return try {
            withContext(Dispatchers.IO) {
                api.verifyDevice(challenge.getString("challenge_id"), Base64Url.encode(signature))
            }
            "FAIL  Modified device signature was accepted\n"
        } catch (error: Exception) {
            "PASS  Modified device signature rejected (${error.message})\n"
        }
    }

    private suspend fun checkReplay(api: ApiClient, registrationId: String): String {
        val challenge = withContext(Dispatchers.IO) { api.deviceChallenge(registrationId) }
        val signature = keys.sign(Base64Url.decode(challenge.getString("challenge")))
        val encoded = Base64Url.encode(signature)
        val id = challenge.getString("challenge_id")
        return try {
            withContext(Dispatchers.IO) { api.verifyDevice(id, encoded) }
            try {
                withContext(Dispatchers.IO) { api.verifyDevice(id, encoded) }
                "FAIL  Replayed device challenge was accepted\n"
            } catch (error: Exception) {
                "PASS  Replayed device challenge rejected (${error.message})\n"
            }
        } catch (error: Exception) {
            "FAIL  Replay setup was rejected before the second submission: ${error.message}\n"
        }
    }

    private suspend fun checkUnknown(api: ApiClient): String {
        return try {
            withContext(Dispatchers.IO) {
                api.deviceChallenge("00000000-0000-0000-0000-000000000099")
            }
            "FAIL  Unknown device was accepted\n"
        } catch (error: Exception) {
            "PASS  Unknown device rejected (${error.message})\n"
        }
    }

    private suspend fun checkWrongKey(api: ApiClient, registrationId: String): String {
        val challenge = withContext(Dispatchers.IO) { api.deviceChallenge(registrationId) }
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val pair = generator.generateKeyPair()
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(pair.private)
        signature.update(Base64Url.decode(challenge.getString("challenge")))
        val encoded = Base64Url.encode(signature.sign())
        return try {
            withContext(Dispatchers.IO) { api.verifyDevice(challenge.getString("challenge_id"), encoded) }
            "FAIL  Incorrect device public key was accepted\n"
        } catch (error: Exception) {
            "PASS  Incorrect device public key rejected (${error.message})\n"
        }
    }

    private fun runServerSuite() {
        val prefs = AppPreferences(this)
        setBusy(true)
        lifecycleScope.launch {
            try {
                val response = withContext(Dispatchers.IO) {
                    ApiClient(prefs.requireHttpsBaseUrl(), prefs.adminToken).negativeTests()
                }
                binding.textSecurityResults.text = formatSuite(response)
            } catch (error: Exception) {
                binding.textSecurityResults.text = "FAIL\n${error.message}"
            } finally {
                setBusy(false)
            }
        }
    }

    private fun formatSuite(response: JSONObject): String {
        val results = response.optJSONArray("results") ?: return "FAIL\nThe suite returned no results."
        return buildString {
            appendLine("Server verifier suite")
            appendLine(response.optString("summary"))
            appendLine()
            for (index in 0 until results.length()) {
                val row = results.getJSONObject(index)
                val mark = if (row.optBoolean("passed")) "PASS" else "FAIL"
                appendLine("$mark  ${row.optString("name")}")
                appendLine("  Expected: ${row.optString("expected")}")
                appendLine("  Actual: ${row.optString("actual")}")
                val detail = row.optString("detail")
                if (detail.isNotBlank()) {
                    appendLine("  $detail")
                }
            }
        }.trim()
    }

    private fun setBusy(busy: Boolean) {
        binding.buttonDeviceChecks.isEnabled = !busy
        binding.buttonServerSuite.isEnabled = !busy
    }
}

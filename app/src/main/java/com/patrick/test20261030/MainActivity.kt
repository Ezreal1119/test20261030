package com.patrick.test20261030

import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.lifecycle.lifecycleScope
import com.patrick.test20261030.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.time.LocalTime
import java.time.format.DateTimeFormatter

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var prefs: AppPreferences
    private val keys = DeviceKeyManager()
    private val credentialManager by lazy { CredentialManager.create(this) }
    private var busy = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        enableEdgeToEdge()
        ViewCompat.setOnApplyWindowInsetsListener(binding.main) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        prefs = AppPreferences(this)
        binding.textDeviceInfo.text = DeviceFacts.describe(this)
        binding.textAssetHost.text = "Digital Asset Links host in this build: " + getString(R.string.asset_links_host)
        loadFields()
        binding.buttonSaveSettings.setOnClickListener { saveSettings() }
        binding.buttonCheckBackend.setOnClickListener { launchOp { checkBackend() } }
        binding.buttonShowFingerprint.setOnClickListener { showFingerprint() }
        binding.buttonPublishFingerprint.setOnClickListener { launchOp { publishFingerprint() } }
        binding.buttonIssueToken.setOnClickListener { launchOp { issueToken() } }
        binding.buttonGenerateKey.setOnClickListener { confirmAndGenerate() }
        binding.buttonInspectKey.setOnClickListener { inspectKey() }
        binding.buttonRegisterDevice.setOnClickListener { launchOp { registerDevice() } }
        binding.buttonTestDeviceAuth.setOnClickListener { launchOp { testDeviceAuth() } }
        binding.buttonRegisterPasskey.setOnClickListener { launchOp { registerPasskey() } }
        binding.buttonAuthenticatePasskey.setOnClickListener { launchOp { authenticatePasskey() } }
        binding.buttonViewCredential.setOnClickListener { launchOp { viewCredentials() } }
        binding.buttonRunComplete.setOnClickListener { launchOp { runComplete() } }
        binding.buttonViewHistory.setOnClickListener {
            startActivity(Intent(this, HistoryActivity::class.java))
        }
        binding.buttonNegativeTests.setOnClickListener {
            startActivity(Intent(this, SecurityTestActivity::class.java))
        }
        binding.buttonExportJson.setOnClickListener { launchOp { exportReport(pdf = false) } }
        binding.buttonExportPdf.setOnClickListener { launchOp { exportReport(pdf = true) } }
        log("Ready. Save the HTTPS backend URL and lab admin token before testing.")
    }

    override fun onResume() {
        super.onResume()
        showRegistration()
    }

    private fun loadFields() {
        binding.editBaseUrl.setText(prefs.baseUrl)
        binding.editAdminToken.setText(prefs.adminToken)
        binding.editUsername.setText(prefs.username.ifBlank { "dt610-operator" })
        binding.editEnrollmentToken.setText(prefs.enrollmentToken)
        showRegistration()
    }

    private fun saveSettings() {
        prefs.baseUrl = binding.editBaseUrl.text?.toString().orEmpty()
        prefs.adminToken = binding.editAdminToken.text?.toString().orEmpty()
        prefs.username = binding.editUsername.text?.toString().orEmpty().ifBlank { "dt610-operator" }
        prefs.enrollmentToken = binding.editEnrollmentToken.text?.toString().orEmpty()
        try {
            prefs.requireHttpsBaseUrl()
            StatusText.show(binding.textSettingsStatus, StatusText.NOT_TESTED, "Settings saved. Check the backend to confirm connectivity.")
            log("Settings saved")
        } catch (error: Exception) {
            StatusText.show(binding.textSettingsStatus, StatusText.FAIL, error.message ?: "Invalid URL")
        }
    }

    private fun showRegistration() {
        val id = prefs.registrationId
        binding.textRegistrationId.text = if (id.isBlank()) {
            "Registration ID: not registered"
        } else {
            "Registration ID: $id"
        }
    }

    private fun confirmAndGenerate() {
        if (keys.hasKey()) {
            AlertDialog.Builder(this)
                .setTitle(R.string.replace_key_title)
                .setMessage(R.string.replace_key_message)
                .setPositiveButton(R.string.replace_key_confirm) { _, _ -> launchOp { generateKey(replace = true) } }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        } else {
            launchOp { generateKey(replace = false) }
        }
    }

    private suspend fun generateKey(replace: Boolean) {
        var challengeId: String? = null
        var challenge: ByteArray? = null
        var note = ""
        val api = try {
            apiClient()
        } catch (error: Exception) {
            note = error.message ?: "Backend is not configured"
            null
        }
        if (api != null) {
            try {
                val response = withContext(Dispatchers.IO) { api.attestationChallenge() }
                challengeId = response.getString("challenge_id")
                challenge = Base64Url.decode(response.getString("challenge"))
            } catch (error: Exception) {
                note = "Attestation challenge was not obtained (${error.message}). The key will be created without a server challenge."
            }
        }
        val inspection = withContext(Dispatchers.IO) {
            if (replace) {
                keys.deleteKey()
            }
            try {
                keys.generate(challenge)
            } catch (error: Exception) {
                if (challenge != null) {
                    note = "Keystore rejected the attestation challenge (${error.message}). Generated a key without attestation."
                    keys.deleteKey()
                    challengeId = null
                    keys.generate(null)
                } else {
                    throw error
                }
            }
        }
        prefs.attestationChallengeId = challengeId.orEmpty()
        val detail = buildString {
            appendLine("Key generated inside Android Keystore. Challenge-response has not been verified yet.")
            appendLine(inspection.detail)
            append(getString(R.string.attestation_unverified))
            if (note.isNotBlank()) {
                append("\n")
                append(note)
            }
        }
        StatusText.show(binding.textDeviceStatus, StatusText.NOT_VERIFIED, detail.trim())
        log("Device key generated. Security level ${inspection.securityLevel}. Exportable ${inspection.privateKeyExportable}.")
    }

    private fun inspectKey() {
        val inspection = keys.inspect()
        if (inspection == null) {
            StatusText.show(binding.textDeviceStatus, StatusText.NOT_TESTED, "No device key exists yet.")
            return
        }
        val detail = inspection.detail + "\n" + getString(R.string.attestation_unverified) +
            "\nKeyInfo above is reported by this device. The backend has not verified attestation in this step."
        StatusText.show(binding.textDeviceStatus, StatusText.NOT_VERIFIED, detail)
        log("Key inspection read security level ${inspection.securityLevel}")
    }

    private suspend fun registerDevice() {
        val inspection = keys.inspect() ?: throw IllegalStateException("Generate a device key first")
        val token = binding.editEnrollmentToken.text?.toString().orEmpty().trim()
        if (token.isBlank()) {
            throw IllegalStateException("Issue or paste an enrollment token first")
        }
        prefs.enrollmentToken = token
        val body = JSONObject()
            .put("enrollment_token", token)
            .put("public_key_spki", Base64Url.encode(inspection.publicKeySpki))
            .put("fingerprint", inspection.fingerprint)
            .put("algorithm", inspection.algorithm)
            .put("security_level", inspection.securityLevel)
            .put("user_authentication_required", inspection.userAuthenticationRequired)
            .put("private_key_exportable", inspection.privateKeyExportable)
            .put("key_alias", inspection.alias)
            .put("device_info", DeviceFacts.json(this))
        val challengeId = prefs.attestationChallengeId
        if (challengeId.isNotBlank()) {
            body.put("attestation_challenge_id", challengeId)
        }
        if (inspection.certificateChain.isNotEmpty()) {
            val chain = JSONArray()
            inspection.certificateChain.forEach { chain.put(Base64Url.encode(it)) }
            body.put("attestation_chain", chain)
        }
        val existing = prefs.registrationId
        if (existing.isNotBlank()) {
            body.put("replace_registration_id", existing)
        }
        val response = withContext(Dispatchers.IO) { apiClient().registerDevice(body) }
        prefs.registrationId = response.getString("registration_id")
        prefs.enrollmentToken = ""
        binding.editEnrollmentToken.setText("")
        showRegistration()
        val attestation = response.optString("attestation_status", getString(R.string.attestation_unverified))
        StatusText.show(
            binding.textDeviceStatus,
            StatusText.PASS,
            "Public key registered.\nRegistration ID: ${prefs.registrationId}\n$attestation\n${inspection.detail}",
        )
        log("Device registered ${prefs.registrationId}")
    }

    private suspend fun testDeviceAuth() {
        val registrationId = requireRegistration()
        val api = apiClient()
        val challenge = withContext(Dispatchers.IO) { api.deviceChallenge(registrationId) }
        val challengeId = challenge.getString("challenge_id")
        val bytes = Base64Url.decode(challenge.getString("challenge"))
        val signature = withContext(Dispatchers.IO) { keys.sign(bytes) }
        val result = withContext(Dispatchers.IO) { api.verifyDevice(challengeId, Base64Url.encode(signature)) }
        StatusText.show(
            binding.textDeviceStatus,
            StatusText.PASS,
            "Backend accepted the Android Keystore signature. This standalone check does not create a session.\n" +
                result.optString("message", "Signature verified."),
        )
        log("Standalone device authentication accepted")
    }

    private suspend fun registerPasskey() {
        if (!ensurePasskeyReady()) {
            return
        }
        val api = apiClient()
        val options = withContext(Dispatchers.IO) {
            api.registrationOptions(currentUsername(), prefs.registrationId)
        }
        val requestJson = options.getString("request_json")
        val challengeId = options.getString("challenge_id")
        log("Opening the system Passkey registration prompt")
        val responseJson = try {
            val result = credentialManager.createCredential(
                this,
                CreatePublicKeyCredentialRequest(requestJson),
            )
            (result as CreatePublicKeyCredentialResponse).registrationResponseJson
        } catch (cancelled: CreateCredentialCancellationException) {
            StatusText.show(binding.textWebauthnStatus, StatusText.FAIL, "Passkey registration was cancelled.")
            log("Passkey registration cancelled")
            return
        } catch (error: CreateCredentialException) {
            StatusText.show(binding.textWebauthnStatus, StatusText.FAIL, error.message ?: error.javaClass.simpleName)
            log("Passkey registration failed: ${error.message}")
            return
        }
        val verified = withContext(Dispatchers.IO) {
            api.registerPasskey(challengeId, responseJson, prefs.registrationId)
        }
        StatusText.show(binding.textWebauthnStatus, StatusText.PASS, verified.optString("summary"))
        log("Passkey registration verified")
    }

    private suspend fun authenticatePasskey() {
        if (!ensurePasskeyReady()) {
            return
        }
        val api = apiClient()
        val options = withContext(Dispatchers.IO) { api.authenticationOptions(currentUsername()) }
        val verified = submitPasskey(api, options.getString("request_json"), options.getString("challenge_id"))
            ?: return
        StatusText.show(binding.textWebauthnStatus, StatusText.PASS, verified.optString("summary"))
        log("Standalone Passkey authentication verified. No session was created.")
    }

    private suspend fun viewCredentials() {
        val response = withContext(Dispatchers.IO) { apiClient().credentialProperties(currentUsername()) }
        StatusText.show(binding.textWebauthnStatus, StatusText.NOT_VERIFIED, response.optString("summary"))
        log("Loaded credential properties")
    }

    private suspend fun runComplete() {
        val startNs = SystemClock.elapsedRealtimeNanos()
        var transactionId = ""
        var deviceEndNs = startNs
        var webauthnEndNs = startNs
        var devicePassed = false
        val api = try {
            apiClient()
        } catch (error: Exception) {
            failIntegrated(error.message ?: "Backend is not configured")
            return
        }
        try {
            requireRegistration()
            val started = withContext(Dispatchers.IO) {
                api.startTransaction(prefs.registrationId, currentUsername())
            }
            transactionId = started.getString("transaction_id")
            val challengeBytes = Base64Url.decode(started.getString("challenge"))
            val signature = withContext(Dispatchers.IO) { keys.sign(challengeBytes) }
            val device = withContext(Dispatchers.IO) {
                api.submitDevice(transactionId, Base64Url.encode(signature))
            }
            deviceEndNs = SystemClock.elapsedRealtimeNanos()
            devicePassed = true
            log("Device authentication accepted for $transactionId. Opening Passkey prompt.")
            val assertion = try {
                val request = GetCredentialRequest.Builder()
                    .addCredentialOption(GetPublicKeyCredentialOption(device.getString("request_json")))
                    .build()
                val result = credentialManager.getCredential(this, request)
                (result.credential as PublicKeyCredential).authenticationResponseJson
            } catch (cancelled: GetCredentialCancellationException) {
                webauthnEndNs = SystemClock.elapsedRealtimeNanos()
                recordFailure(api, transactionId, startNs, deviceEndNs, webauthnEndNs, "PASS", "FAIL", "User cancelled Passkey verification")
                failIntegrated("User cancelled Passkey verification. No session was opened.")
                return
            } catch (error: GetCredentialException) {
                webauthnEndNs = SystemClock.elapsedRealtimeNanos()
                val reason = error.message ?: error.javaClass.simpleName
                recordFailure(api, transactionId, startNs, deviceEndNs, webauthnEndNs, "PASS", "FAIL", reason)
                failIntegrated(reason)
                return
            }
            val web = withContext(Dispatchers.IO) { api.submitWebAuthn(transactionId, assertion) }
            webauthnEndNs = SystemClock.elapsedRealtimeNanos()
            val sessionToken = web.getString("session_token")
            var confirmed: JSONObject? = null
            var confirmError: Exception? = null
            repeat(3) { attempt ->
                if (confirmed == null) {
                    if (attempt > 0) {
                        delay(400)
                    }
                    try {
                        val check = withContext(Dispatchers.IO) { api.confirmSession(sessionToken) }
                        if (check.optBoolean("active")) {
                            confirmed = check
                        }
                    } catch (error: Exception) {
                        confirmError = error
                    }
                }
            }
            val session = confirmed
            if (session == null || !session.optBoolean("active")) {
                failIntegrated(confirmError?.message ?: "Backend did not confirm an active session. Home screen was not opened.")
                return
            }
            val intent = Intent(this, AuthenticatedHomeActivity::class.java)
                .putExtra(AuthenticatedHomeActivity.EXTRA_START_NS, startNs)
                .putExtra(AuthenticatedHomeActivity.EXTRA_DEVICE_END_NS, deviceEndNs)
                .putExtra(AuthenticatedHomeActivity.EXTRA_WEBAUTHN_END_NS, webauthnEndNs)
                .putExtra(AuthenticatedHomeActivity.EXTRA_TRANSACTION_ID, transactionId)
                .putExtra(AuthenticatedHomeActivity.EXTRA_REGISTRATION_ID, prefs.registrationId)
                .putExtra(AuthenticatedHomeActivity.EXTRA_USERNAME, currentUsername())
                .putExtra(AuthenticatedHomeActivity.EXTRA_SESSION_TOKEN, sessionToken)
                .putExtra(AuthenticatedHomeActivity.EXTRA_EXPIRES, session.optString("expires_at"))
                .putExtra(AuthenticatedHomeActivity.EXTRA_NETWORK, DeviceFacts.networkType(this))
            startActivity(intent)
            StatusText.show(
                binding.textIntegratedStatus,
                StatusText.PASS,
                "Backend confirmed the session. Duration is shown on the authenticated home screen.",
            )
            log("Session confirmed for $transactionId")
        } catch (error: Exception) {
            val now = SystemClock.elapsedRealtimeNanos()
            if (deviceEndNs == startNs) {
                deviceEndNs = now
            }
            if (webauthnEndNs < deviceEndNs) {
                webauthnEndNs = now
            }
            if (transactionId.isNotBlank()) {
                recordFailure(
                    api,
                    transactionId,
                    startNs,
                    deviceEndNs,
                    maxOf(webauthnEndNs, now),
                    if (devicePassed) "PASS" else "FAIL",
                    "FAIL",
                    error.message ?: "Authentication failed",
                )
            }
            failIntegrated(error.message ?: "Authentication failed")
        }
    }

    private suspend fun recordFailure(
        api: ApiClient,
        transactionId: String,
        startNs: Long,
        deviceEndNs: Long,
        webauthnEndNs: Long,
        deviceResult: String,
        webauthnResult: String,
        reason: String,
    ) {
        val finish = SystemClock.elapsedRealtimeNanos()
        val safeWebEnd = maxOf(webauthnEndNs, deviceEndNs)
        val safeFinish = maxOf(finish, safeWebEnd)
        try {
            withContext(Dispatchers.IO) { api.cancelTransaction(transactionId, reason) }
            val timing = Timing.segments(startNs, deviceEndNs, safeWebEnd, safeFinish)
            val body = JSONObject()
                .put("transaction_id", transactionId)
                .put("registration_id", prefs.registrationId)
                .put("total_ms", timing.totalMs)
                .put("device_ms", timing.deviceMs)
                .put("webauthn_ms", timing.webauthnMs)
                .put("session_ms", timing.sessionMs)
                .put("device_result", deviceResult)
                .put("webauthn_result", webauthnResult)
                .put("session_result", "FAIL")
                .put("network_type", DeviceFacts.networkType(this))
                .put("failure_reason", reason)
                .put("device_info", DeviceFacts.json(this))
            withContext(Dispatchers.IO) { api.recordAttempt(body) }
            log("Recorded failed attempt ${timing.totalMs} ms")
        } catch (error: Exception) {
            log("Failed attempt was not stored: ${error.message}")
        }
    }

    private fun failIntegrated(message: String) {
        StatusText.show(binding.textIntegratedStatus, StatusText.FAIL, message)
        log(message)
    }

    private suspend fun submitPasskey(api: ApiClient, requestJson: String, challengeId: String): JSONObject? {
        log("Opening the system Passkey prompt")
        val responseJson = try {
            val request = GetCredentialRequest.Builder()
                .addCredentialOption(GetPublicKeyCredentialOption(requestJson))
                .build()
            val result = credentialManager.getCredential(this, request)
            (result.credential as PublicKeyCredential).authenticationResponseJson
        } catch (cancelled: GetCredentialCancellationException) {
            StatusText.show(binding.textWebauthnStatus, StatusText.FAIL, "Passkey authentication was cancelled.")
            log("Passkey authentication cancelled")
            return null
        } catch (error: GetCredentialException) {
            StatusText.show(binding.textWebauthnStatus, StatusText.FAIL, error.message ?: error.javaClass.simpleName)
            log("Passkey authentication failed: ${error.message}")
            return null
        }
        return withContext(Dispatchers.IO) { api.authenticatePasskey(challengeId, responseJson) }
    }

    private suspend fun ensurePasskeyReady(): Boolean {
        val health = withContext(Dispatchers.IO) { apiClient().health() }
        val rpId = health.optString("rp_id")
        val baked = getString(R.string.asset_links_host)
        if (rpId != baked) {
            StatusText.show(
                binding.textWebauthnStatus,
                StatusText.FAIL,
                "Backend RP ID '$rpId' does not match this build's asset links host '$baked'. Set rpHost in gradle.properties and RP_ID on the backend to the same hostname, then rebuild.",
            )
            return false
        }
        if (!health.optBoolean("fingerprints_configured")) {
            StatusText.show(
                binding.textWebauthnStatus,
                StatusText.NOT_VERIFIED,
                "Publish this app signing certificate fingerprint before registering a Passkey.",
            )
            return false
        }
        return true
    }

    private suspend fun checkBackend() {
        val health = withContext(Dispatchers.IO) { apiClient().health() }
        val detail = buildString {
            appendLine("Backend ${health.optString("version")} is reachable.")
            appendLine("RP ID: ${health.optString("rp_id")}")
            appendLine("Origin: ${health.optString("origin")}")
            appendLine("Fingerprints configured: ${health.optBoolean("fingerprints_configured")}")
            appendLine("Attestation roots loaded: ${health.optInt("attestation_roots")}")
            append("Asset links host in this build: ${getString(R.string.asset_links_host)}")
        }
        val status = if (health.optBoolean("rp_configured") && health.optBoolean("fingerprints_configured")) {
            StatusText.PASS
        } else {
            StatusText.NOT_VERIFIED
        }
        StatusText.show(binding.textSettingsStatus, status, detail.trim())
        log("Backend health checked")
    }

    private fun showFingerprint() {
        val prints = DeviceFacts.signingFingerprints(this)
        val text = if (prints.isEmpty()) {
            "No signing certificate was returned by PackageManager."
        } else {
            "Package: $packageName\nSHA-256:\n" + prints.joinToString("\n")
        }
        StatusText.show(binding.textSettingsStatus, StatusText.NOT_TESTED, text)
        log("Displayed signing certificate fingerprint")
    }

    private suspend fun publishFingerprint() {
        val prints = DeviceFacts.signingFingerprints(this)
        if (prints.isEmpty()) {
            throw IllegalStateException("No signing certificate fingerprint is available")
        }
        val response = withContext(Dispatchers.IO) {
            apiClient().publishFingerprints(packageName, prints)
        }
        StatusText.show(binding.textSettingsStatus, StatusText.PASS, response.optString("message"))
        log("Published signing certificate fingerprint")
    }

    private suspend fun issueToken() {
        val response = withContext(Dispatchers.IO) { apiClient().issueEnrollmentToken() }
        val token = response.getString("enrollment_token")
        prefs.enrollmentToken = token
        binding.editEnrollmentToken.setText(token)
        StatusText.show(
            binding.textSettingsStatus,
            StatusText.PASS,
            "Enrollment token issued. It is single-use and expires at ${response.optString("expires_at")}.",
        )
        log("Enrollment token issued")
    }

    private suspend fun exportReport(pdf: Boolean) {
        val bytes = withContext(Dispatchers.IO) {
            val api = apiClient()
            if (pdf) api.reportPdf() else api.reportJson()
        }
        val stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").format(LocalTime.now())
        val name = if (pdf) "dt610-auth-report-$stamp.pdf" else "dt610-auth-report-$stamp.json"
        val mime = if (pdf) "application/pdf" else "application/json"
        ReportExporter.export(this, bytes, name, mime)
        StatusText.show(binding.textEvidenceStatus, StatusText.PASS, "Saved $name to Downloads/DT610Auth and opened the share sheet.")
        log("Exported $name")
    }

    private fun requireRegistration(): String {
        val id = prefs.registrationId
        if (id.isBlank()) {
            throw IllegalStateException("Register the device before this step")
        }
        return id
    }

    private fun currentUsername(): String {
        return binding.editUsername.text?.toString().orEmpty().trim().ifBlank { "dt610-operator" }
    }

    private fun apiClient(): ApiClient {
        saveSettingsQuietly()
        if (prefs.adminToken.isBlank()) {
            throw IllegalArgumentException("Enter the lab admin token")
        }
        return ApiClient(prefs.requireHttpsBaseUrl(), prefs.adminToken)
    }

    private fun saveSettingsQuietly() {
        prefs.baseUrl = binding.editBaseUrl.text?.toString().orEmpty()
        prefs.adminToken = binding.editAdminToken.text?.toString().orEmpty()
        prefs.username = currentUsername()
        prefs.enrollmentToken = binding.editEnrollmentToken.text?.toString().orEmpty()
    }

    private fun launchOp(block: suspend () -> Unit) {
        if (busy) {
            return
        }
        busy = true
        setButtonsEnabled(false)
        lifecycleScope.launch {
            try {
                block()
            } catch (error: Exception) {
                val message = error.message ?: error.javaClass.simpleName
                log(message)
                Toast.makeText(this@MainActivity, message, Toast.LENGTH_LONG).show()
            } finally {
                busy = false
                setButtonsEnabled(true)
            }
        }
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        listOf(
            binding.buttonSaveSettings,
            binding.buttonCheckBackend,
            binding.buttonShowFingerprint,
            binding.buttonPublishFingerprint,
            binding.buttonIssueToken,
            binding.buttonGenerateKey,
            binding.buttonInspectKey,
            binding.buttonRegisterDevice,
            binding.buttonTestDeviceAuth,
            binding.buttonRegisterPasskey,
            binding.buttonAuthenticatePasskey,
            binding.buttonViewCredential,
            binding.buttonRunComplete,
            binding.buttonViewHistory,
            binding.buttonNegativeTests,
            binding.buttonExportJson,
            binding.buttonExportPdf,
        ).forEach { button -> button.isEnabled = enabled }
    }

    private fun log(message: String) {
        val stamp = DateTimeFormatter.ofPattern("HH:mm:ss").format(LocalTime.now())
        binding.textLog.append("[$stamp] $message\n")
    }
}

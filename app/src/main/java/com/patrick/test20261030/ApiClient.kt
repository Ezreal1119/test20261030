package com.patrick.test20261030

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class ApiException(message: String) : Exception(message)

class ApiClient(baseUrl: String, private val adminToken: String) {
    private val root = baseUrl.trim().trimEnd('/')
    private val http = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(40, TimeUnit.SECONDS)
        .writeTimeout(40, TimeUnit.SECONDS)
        .build()
    private val jsonType = "application/json; charset=utf-8".toMediaType()

    fun health(): JSONObject = get("/api/health")

    fun publishFingerprints(packageName: String, fingerprints: List<String>): JSONObject {
        val body = JSONObject()
            .put("package_name", packageName)
            .put("sha256_cert_fingerprints", JSONArray(fingerprints))
        return put("/api/admin/assetlinks", body)
    }

    fun issueEnrollmentToken(): JSONObject = post("/api/admin/enrollment-tokens", JSONObject())

    fun attestationChallenge(): JSONObject = post("/api/device/attestation-challenge", JSONObject())

    fun registerDevice(body: JSONObject): JSONObject = post("/api/device/register", body)

    fun deviceChallenge(registrationId: String): JSONObject {
        return post("/api/device/challenge", JSONObject().put("registration_id", registrationId))
    }

    fun verifyDevice(challengeId: String, signature: String): JSONObject {
        val body = JSONObject()
            .put("challenge_id", challengeId)
            .put("signature", signature)
        return post("/api/device/verify", body)
    }

    fun registrationOptions(username: String, registrationId: String): JSONObject {
        val body = JSONObject().put("username", username)
        if (registrationId.isNotBlank()) {
            body.put("registration_id", registrationId)
        }
        return post("/api/webauthn/registration/options", body)
    }

    fun registerPasskey(challengeId: String, credentialJson: String, registrationId: String): JSONObject {
        val body = JSONObject()
            .put("challenge_id", challengeId)
            .put("credential_json", credentialJson)
        if (registrationId.isNotBlank()) {
            body.put("registration_id", registrationId)
        }
        return post("/api/webauthn/registration", body)
    }

    fun authenticationOptions(username: String): JSONObject {
        return post("/api/webauthn/authentication/options", JSONObject().put("username", username))
    }

    fun authenticatePasskey(challengeId: String, credentialJson: String): JSONObject {
        val body = JSONObject()
            .put("challenge_id", challengeId)
            .put("credential_json", credentialJson)
        return post("/api/webauthn/authentication", body)
    }

    fun credentialProperties(username: String): JSONObject {
        return get("/api/webauthn/credentials?username=" + java.net.URLEncoder.encode(username, "UTF-8"))
    }

    fun startTransaction(registrationId: String, username: String): JSONObject {
        val body = JSONObject()
            .put("registration_id", registrationId)
            .put("username", username)
        return post("/api/auth/transactions", body)
    }

    fun submitDevice(transactionId: String, signature: String): JSONObject {
        return post(
            "/api/auth/transactions/$transactionId/device",
            JSONObject().put("signature", signature),
        )
    }

    fun submitWebAuthn(transactionId: String, credentialJson: String): JSONObject {
        return post(
            "/api/auth/transactions/$transactionId/webauthn",
            JSONObject().put("credential_json", credentialJson),
        )
    }

    fun cancelTransaction(transactionId: String, reason: String): JSONObject {
        return post(
            "/api/auth/transactions/$transactionId/cancel",
            JSONObject().put("reason", reason),
        )
    }

    fun confirmSession(sessionToken: String): JSONObject = get("/api/auth/session", sessionToken)

    fun logout(sessionToken: String): JSONObject = post("/api/auth/logout", JSONObject(), sessionToken)

    fun recordAttempt(body: JSONObject): JSONObject = post("/api/auth/attempts", body)

    fun attempts(registrationId: String): JSONObject {
        val query = if (registrationId.isBlank()) "" else "?registration_id=" +
            java.net.URLEncoder.encode(registrationId, "UTF-8")
        return get("/api/auth/attempts$query")
    }

    fun negativeTests(): JSONObject = post("/api/security/negative-tests", JSONObject())

    fun reportJson(): ByteArray = getBytes("/api/reports/evidence.json")

    fun reportPdf(): ByteArray = getBytes("/api/reports/evidence.pdf")

    private fun get(path: String, sessionToken: String? = null): JSONObject {
        val request = baseRequest(path, sessionToken).get().build()
        return executeJson(request)
    }

    private fun post(path: String, body: JSONObject, sessionToken: String? = null): JSONObject {
        val request = baseRequest(path, sessionToken)
            .post(body.toString().toRequestBody(jsonType))
            .build()
        return executeJson(request)
    }

    private fun put(path: String, body: JSONObject): JSONObject {
        val request = baseRequest(path, null)
            .put(body.toString().toRequestBody(jsonType))
            .build()
        return executeJson(request)
    }

    private fun getBytes(path: String): ByteArray {
        val request = baseRequest(path, null).get().build()
        http.newCall(request).execute().use { response ->
            val bytes = response.body?.bytes() ?: ByteArray(0)
            if (!response.isSuccessful) {
                throw ApiException(errorMessage(response.code, bytes.toString(Charsets.UTF_8)))
            }
            return bytes
        }
    }

    private fun executeJson(request: Request): JSONObject {
        http.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(errorMessage(response.code, text))
            }
            val json = if (text.isBlank()) JSONObject() else JSONObject(text)
            if (json.has("ok") && !json.optBoolean("ok")) {
                throw ApiException(json.optString("error", "Backend returned ok=false"))
            }
            return json
        }
    }

    private fun baseRequest(path: String, sessionToken: String?): Request.Builder {
        val builder = Request.Builder()
            .url((root + path).toHttpUrl())
            .header("Accept", "application/json")
            .header("X-Admin-Token", adminToken)
        if (!sessionToken.isNullOrBlank()) {
            builder.header("Authorization", "Bearer $sessionToken")
        }
        return builder
    }

    private fun errorMessage(code: Int, body: String): String {
        return try {
            val json = JSONObject(body)
            json.optString("error", "HTTP $code")
        } catch (_: Exception) {
            "HTTP $code ${body.take(300)}"
        }
    }
}

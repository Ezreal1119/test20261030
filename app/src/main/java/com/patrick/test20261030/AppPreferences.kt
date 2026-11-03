package com.patrick.test20261030

import android.content.Context

class AppPreferences(context: Context) {
    private val prefs = context.getSharedPreferences("dt610_verification", Context.MODE_PRIVATE)

    var baseUrl: String
        get() = prefs.getString(KEY_BASE_URL, "") ?: ""
        set(value) = prefs.edit().putString(KEY_BASE_URL, value.trim().trimEnd('/')).apply()

    var adminToken: String
        get() = prefs.getString(KEY_ADMIN_TOKEN, "") ?: ""
        set(value) = prefs.edit().putString(KEY_ADMIN_TOKEN, value.trim()).apply()

    var username: String
        get() = prefs.getString(KEY_USERNAME, "dt610-operator") ?: "dt610-operator"
        set(value) = prefs.edit().putString(KEY_USERNAME, value.trim()).apply()

    var enrollmentToken: String
        get() = prefs.getString(KEY_ENROLLMENT, "") ?: ""
        set(value) = prefs.edit().putString(KEY_ENROLLMENT, value.trim()).apply()

    var registrationId: String
        get() = prefs.getString(KEY_REGISTRATION, "") ?: ""
        set(value) = prefs.edit().putString(KEY_REGISTRATION, value.trim()).apply()

    var attestationChallengeId: String
        get() = prefs.getString(KEY_ATTESTATION, "") ?: ""
        set(value) = prefs.edit().putString(KEY_ATTESTATION, value.trim()).apply()

    fun requireHttpsBaseUrl(): String {
        val url = baseUrl.trim().trimEnd('/')
        val scheme = url.substringBefore("://").lowercase()
        if (scheme != "https" || !url.startsWith("https://") || url.length <= "https://".length) {
            throw IllegalArgumentException("Backend URL must be an https:// address")
        }
        return url
    }

    companion object {
        private const val KEY_BASE_URL = "base_url"
        private const val KEY_ADMIN_TOKEN = "admin_token"
        private const val KEY_USERNAME = "username"
        private const val KEY_ENROLLMENT = "enrollment_token"
        private const val KEY_REGISTRATION = "registration_id"
        private const val KEY_ATTESTATION = "attestation_challenge_id"
    }
}

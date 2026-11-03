package com.patrick.test20261030

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import org.json.JSONObject
import java.security.MessageDigest

object DeviceFacts {
    fun describe(context: Context): String {
        return buildString {
            appendLine("Manufacturer: ${Build.MANUFACTURER}")
            appendLine("Model: ${Build.MODEL}")
            appendLine("Android version: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            appendLine("Build number: ${Build.DISPLAY}")
            appendLine("Security patch: ${Build.VERSION.SECURITY_PATCH}")
            appendLine("Fingerprint: ${Build.FINGERPRINT}")
            append("App version: ${appVersion(context)}")
        }
    }

    fun json(context: Context): JSONObject {
        return JSONObject()
            .put("manufacturer", Build.MANUFACTURER)
            .put("model", Build.MODEL)
            .put("android_version", Build.VERSION.RELEASE)
            .put("sdk_int", Build.VERSION.SDK_INT)
            .put("build_number", Build.DISPLAY)
            .put("security_patch", Build.VERSION.SECURITY_PATCH)
            .put("fingerprint", Build.FINGERPRINT)
            .put("app_version", appVersion(context))
    }

    fun appVersion(context: Context): String {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        return info.versionName ?: "unknown"
    }

    fun networkType(context: Context): String {
        val manager = context.getSystemService(ConnectivityManager::class.java) ?: return "UNKNOWN"
        val network = manager.activeNetwork ?: return "NONE"
        val caps = manager.getNetworkCapabilities(network) ?: return "UNKNOWN"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WIFI"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "CELLULAR"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            else -> "OTHER"
        }
    }

    fun signingFingerprints(context: Context): List<String> {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_SIGNING_CERTIFICATES,
        )
        val signing = info.signingInfo ?: return emptyList()
        val certs = if (signing.hasMultipleSigners()) {
            signing.apkContentsSigners
        } else {
            signing.signingCertificateHistory
        }
        return certs.map { certificate ->
            val digest = MessageDigest.getInstance("SHA-256").digest(certificate.toByteArray())
            digest.joinToString(":") { byte -> "%02X".format(byte) }
        }.distinct()
    }
}

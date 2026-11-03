package com.patrick.test20261030

import android.util.Base64

object Base64Url {
    fun encode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    fun decode(value: String): ByteArray {
        var padded = value.trim()
        val remainder = padded.length % 4
        if (remainder != 0) {
            padded += "=".repeat(4 - remainder)
        }
        return Base64.decode(padded, Base64.URL_SAFE or Base64.NO_WRAP)
    }
}

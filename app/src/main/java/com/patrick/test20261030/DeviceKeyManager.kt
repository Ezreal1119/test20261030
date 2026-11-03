package com.patrick.test20261030

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.security.auth.x500.X500Principal

data class KeyInspection(
    val alias: String,
    val algorithm: String,
    val fingerprint: String,
    val securityLevel: String,
    val userAuthenticationRequired: Boolean,
    val privateKeyExportable: Boolean,
    val publicKeySpki: ByteArray,
    val certificateChain: List<ByteArray>,
    val detail: String,
)

class DeviceKeyManager {
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun hasKey(): Boolean = keyStore.containsAlias(ALIAS)

    fun deleteKey() {
        if (keyStore.containsAlias(ALIAS)) {
            keyStore.deleteEntry(ALIAS)
        }
    }

    fun generate(attestationChallenge: ByteArray?): KeyInspection {
        if (keyStore.containsAlias(ALIAS)) {
            throw IllegalStateException("A device key already exists. Confirm replacement before generating another.")
        }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val now = System.currentTimeMillis()
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .setCertificateSubject(X500Principal("CN=DT610 Device Authentication"))
            .setCertificateSerialNumber(BigInteger.ONE)
            .setCertificateNotBefore(Date(now))
            .setCertificateNotAfter(Date(now + TEN_YEARS_MS))
        if (attestationChallenge != null) {
            builder.setAttestationChallenge(attestationChallenge)
        }
        generator.initialize(builder.build())
        generator.generateKeyPair()
        return inspect() ?: throw IllegalStateException("Key generation did not produce an Android Keystore entry")
    }

    fun inspect(): KeyInspection? {
        if (!keyStore.containsAlias(ALIAS)) {
            return null
        }
        val privateKey = keyStore.getKey(ALIAS, null) as PrivateKey
        val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(privateKey, KeyInfo::class.java)
        val certificate = keyStore.getCertificate(ALIAS)
            ?: throw IllegalStateException("Android Keystore entry has no certificate")
        val spki = certificate.publicKey.encoded
        val fingerprint = fingerprint(spki)
        val exportable = privateKey.encoded != null && privateKey.encoded.isNotEmpty()
        val level = securityLevel(info)
        val chain = keyStore.getCertificateChain(ALIAS)?.map { it.encoded } ?: emptyList()
        val userAuth = info.isUserAuthenticationRequired
        val detail = buildString {
            appendLine("Algorithm: EC P-256 with SHA-256")
            appendLine("Key alias: $ALIAS")
            appendLine("Public key fingerprint (SHA-256 of SPKI): $fingerprint")
            appendLine("Key security level: $level")
            appendLine("User authentication required: $userAuth")
            appendLine("Private key exportable through standard Android APIs: $exportable")
            appendLine("Certificate chain length: ${chain.size}")
            append("Keystore provider: $ANDROID_KEYSTORE")
        }
        return KeyInspection(
            alias = ALIAS,
            algorithm = "ECDSA P-256 SHA-256",
            fingerprint = fingerprint,
            securityLevel = level,
            userAuthenticationRequired = userAuth,
            privateKeyExportable = exportable,
            publicKeySpki = spki,
            certificateChain = chain,
            detail = detail.trim(),
        )
    }

    fun sign(data: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("No Android Keystore signing key is available")
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    private fun securityLevel(info: KeyInfo): String {
        if (Build.VERSION.SDK_INT >= 31) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TRUSTED_ENVIRONMENT"
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX"
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "UNKNOWN_SECURE"
                else -> "UNKNOWN"
            }
        }
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) "TRUSTED_ENVIRONMENT" else "SOFTWARE"
    }

    private fun fingerprint(spki: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(spki)
        return digest.joinToString(":") { byte -> "%02X".format(byte) }
    }

    companion object {
        const val ALIAS = "dt610_device_auth_p256"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TEN_YEARS_MS = 1000L * 60L * 60L * 24L * 365L * 10L
    }
}

package com.patrick.test20261030

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import androidx.core.content.FileProvider
import java.io.File

object ReportExporter {
    fun export(context: Context, bytes: ByteArray, displayName: String, mime: String) {
        val downloadUri = saveToDownloads(context, bytes, displayName, mime)
        val cacheFile = File(context.cacheDir, "reports").apply { mkdirs() }
        val local = File(cacheFile, displayName)
        local.writeBytes(bytes)
        val shareUri = FileProvider.getUriForFile(
            context,
            context.packageName + ".fileprovider",
            local,
        )
        val share = Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, shareUri)
            putExtra(Intent.EXTRA_SUBJECT, displayName)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(share, displayName))
        if (downloadUri == null) {
            throw IllegalStateException("The share sheet was opened, but saving to Downloads failed")
        }
    }

    private fun saveToDownloads(context: Context, bytes: ByteArray, displayName: String, mime: String): Uri? {
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, displayName)
            put(MediaStore.Downloads.MIME_TYPE, mime)
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/DT610Auth")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: return null
        context.contentResolver.openOutputStream(uri)?.use { stream -> stream.write(bytes) }
            ?: return null
        values.clear()
        values.put(MediaStore.Downloads.IS_PENDING, 0)
        context.contentResolver.update(uri, values, null, null)
        return uri
    }
}

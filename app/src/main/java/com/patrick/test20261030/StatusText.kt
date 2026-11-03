package com.patrick.test20261030

import android.graphics.Typeface
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.widget.TextView

object StatusText {
    const val PASS = "PASS"
    const val FAIL = "FAIL"
    const val NOT_TESTED = "NOT TESTED"
    const val NOT_VERIFIED = "NOT VERIFIED"

    fun show(view: TextView, status: String, detail: String) {
        val color = when (status) {
            PASS -> 0xFF1B7F4E.toInt()
            FAIL -> 0xFFA12622.toInt()
            NOT_VERIFIED -> 0xFF8A5A00.toInt()
            else -> 0xFF5C6B73.toInt()
        }
        val text = status + "\n" + detail
        val span = SpannableString(text)
        span.setSpan(ForegroundColorSpan(color), 0, status.length, SpannableString.SPAN_EXCLUSIVE_EXCLUSIVE)
        span.setSpan(StyleSpan(Typeface.BOLD), 0, status.length, SpannableString.SPAN_EXCLUSIVE_EXCLUSIVE)
        view.text = span
    }
}

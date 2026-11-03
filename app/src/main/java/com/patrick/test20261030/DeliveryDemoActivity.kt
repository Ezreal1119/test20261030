package com.patrick.test20261030

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.patrick.test20261030.databinding.ActivityDeliveryDemoBinding
import kotlin.random.Random

class DeliveryDemoActivity : AppCompatActivity() {
    private lateinit var binding: ActivityDeliveryDemoBinding
    private var barcode: String = ""
    private var finished: Boolean = false
    private var sampleIndex: Int = -1

    private val scanReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            applyScan(intent)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDeliveryDemoBinding.inflate(layoutInflater)
        setContentView(binding.root)
        enableEdgeToEdge()
        ViewCompat.setOnApplyWindowInsetsListener(binding.deliveryRoot) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        binding.buttonConfirm.setOnClickListener { confirm() }
        binding.buttonScanAgain.setOnClickListener { resetForm() }
        if (savedInstanceState != null) {
            barcode = savedInstanceState.getString(STATE_BARCODE).orEmpty()
            finished = savedInstanceState.getBoolean(STATE_FINISHED)
            sampleIndex = savedInstanceState.getInt(STATE_SAMPLE, -1)
            if (barcode.isNotEmpty() && sampleIndex in SAMPLES.indices) {
                showParcel(barcode, keepEdits = true)
                if (finished) showFinished()
            }
        } else {
            applyScan(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        applyScan(intent)
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(SCAN_ACTION)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(scanReceiver, filter, RECEIVER_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(scanReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(scanReceiver)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_BARCODE, barcode)
        outState.putBoolean(STATE_FINISHED, finished)
        outState.putInt(STATE_SAMPLE, sampleIndex)
    }

    private fun applyScan(intent: Intent?) {
        if (intent?.action != SCAN_ACTION) return
        val value = intent.getStringExtra(SCAN_EXTRA)?.trim().orEmpty()
        if (value.isEmpty()) return
        barcode = value
        finished = false
        sampleIndex = Random.nextInt(SAMPLES.size)
        showParcel(value, keepEdits = false)
    }

    private fun showParcel(value: String, keepEdits: Boolean) {
        val sample = SAMPLES[sampleIndex]
        binding.textStep.setTextColor(getColor(R.color.teal))
        binding.textStep.text = "Barcode read. Review or edit the details."
        binding.textBarcode.text = value
        if (!keepEdits) {
            binding.editRecipient.setText(sample.recipient)
            binding.editAddress.setText(sample.recipientLocation)
            binding.editNote.setText("")
        }
        setEditingEnabled(true)
        binding.buttonConfirm.isEnabled = true
    }

    private fun confirm() {
        if (barcode.isEmpty() || sampleIndex !in SAMPLES.indices) return
        val sample = SAMPLES[sampleIndex]
        val recipient = binding.editRecipient.text.toString().trim().ifEmpty { sample.recipient }
        val recipientLocation = binding.editAddress.text.toString().trim().ifEmpty { sample.recipientLocation }
        val message = buildString {
            append("Barcode\n")
            append(barcode)
            append("\n\nSender\n")
            append(sample.sender)
            append("\n")
            append(sample.senderLocation)
            append("\n\nRecipient\n")
            append(recipient)
            append("\n")
            append(recipientLocation)
        }
        AlertDialog.Builder(this)
            .setTitle("Package details")
            .setMessage(message)
            .setPositiveButton("Confirm") { _, _ ->
                finished = true
                showFinished()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showFinished() {
        binding.textStep.text = "Task complete"
        binding.textStep.setTextColor(getColor(R.color.pass_green))
        setEditingEnabled(false)
        binding.buttonConfirm.isEnabled = false
    }

    private fun resetForm() {
        barcode = ""
        finished = false
        sampleIndex = -1
        binding.textStep.text = "Press the scan key"
        binding.textStep.setTextColor(getColor(R.color.teal))
        binding.textBarcode.text = "Waiting for a scan"
        binding.editRecipient.setText("")
        binding.editAddress.setText("")
        binding.editNote.setText("")
        setEditingEnabled(false)
        binding.buttonConfirm.isEnabled = false
    }

    private fun setEditingEnabled(enabled: Boolean) {
        binding.editRecipient.isEnabled = enabled
        binding.editAddress.isEnabled = enabled
        binding.editNote.isEnabled = enabled
    }

    private data class Parcel(
        val recipient: String,
        val recipientLocation: String,
        val sender: String,
        val senderLocation: String,
    )

    companion object {
        const val SCAN_ACTION = "android.intent.ACTION_DECODE_DATA"
        const val SCAN_EXTRA = "barcode_string"
        private const val STATE_BARCODE = "barcode"
        private const val STATE_FINISHED = "finished"
        private const val STATE_SAMPLE = "sample"

        private val SAMPLES = listOf(
            Parcel("Anna Brooks", "18 King Street, London", "David Chen", "Shenzhen Sorting Centre, Nanshan"),
            Parcel("Ben Carter", "42 Queen Road, Hong Kong", "Li Wei", "Guangzhou Hub, Baiyun"),
            Parcel("Chloe Adams", "9 Orchard Road, Singapore", "Wang Fang", "Shanghai Depot, Pudong"),
            Parcel("Daniel Wright", "210 Market Street, San Francisco", "Zhang Min", "Dongguan Warehouse, Chang'an"),
            Parcel("Emma Hughes", "77 George Street, Sydney", "Liu Yang", "Beijing Hub, Shunyi"),
            Parcel("Finn Murphy", "15 Grafton Street, Dublin", "Chen Hao", "Hangzhou Depot, Xiaoshan"),
            Parcel("Grace Patel", "88 Brigade Road, Bengaluru", "Zhao Lin", "Chengdu Sorting Centre, Shuangliu"),
            Parcel("Henry Nguyen", "26 Nguyen Hue, Ho Chi Minh City", "Sun Qiang", "Yiwu Warehouse, Futian"),
            Parcel("Isla Campbell", "5 Princes Street, Edinburgh", "Huang Jie", "Xiamen Port Depot, Huli"),
            Parcel("Jack Robinson", "130 Collins Street, Melbourne", "Wu Ting", "Ningbo Hub, Beilun"),
            Parcel("Kate Sullivan", "64 Bay Street, Toronto", "Zhou Yan", "Qingdao Depot, Shibei"),
            Parcel("Leo Martins", "12 Avenida Paulista, Sao Paulo", "Xu Peng", "Foshan Warehouse, Nanhai"),
            Parcel("Maya Rossi", "33 Via Roma, Milan", "He Jing", "Wuhan Sorting Centre, Jianghan"),
            Parcel("Noah Keller", "8 Friedrichstrasse, Berlin", "Gao Bo", "Nanjing Hub, Jiangning"),
            Parcel("Olivia Berg", "19 Drottninggatan, Stockholm", "Ma Li", "Tianjin Port Depot, Binhai"),
            Parcel("Paul Dubois", "47 Rue de Rivoli, Paris", "Tang Wei", "Suzhou Warehouse, Wuzhong"),
            Parcel("Quinn Harris", "250 Park Avenue, New York", "Deng Chao", "Changsha Depot, Yuhua"),
            Parcel("Ruby Clark", "11 Lambton Quay, Wellington", "Cao Ying", "Zhuhai Hub, Xiangzhou"),
            Parcel("Samir Khan", "90 Sheikh Zayed Road, Dubai", "Jiang Tao", "Zhengzhou Sorting Centre, Erqi"),
            Parcel("Tina Vogel", "22 Damrak, Amsterdam", "Shen Rui", "Kunming Depot, Guandu"),
        )
    }
}

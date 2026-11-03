package com.patrick.test20261030

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.patrick.test20261030.databinding.ActivityMenuBinding

class MenuActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val binding = ActivityMenuBinding.inflate(layoutInflater)
        setContentView(binding.root)
        enableEdgeToEdge()
        ViewCompat.setOnApplyWindowInsetsListener(binding.menuRoot) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        binding.buttonOpenAuth.setOnClickListener {
            startActivity(Intent(this, MainActivity::class.java))
        }
        binding.buttonOpenDelivery.setOnClickListener {
            startActivity(Intent(this, DeliveryDemoActivity::class.java))
        }
        binding.buttonOpenAi.setOnClickListener {
            startActivity(Intent(this, OnDeviceAiActivity::class.java))
        }
        binding.buttonOpenPodCamera.setOnClickListener {
            startActivity(Intent(this, PodCameraActivity::class.java))
        }
    }
}

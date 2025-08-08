package com.kkrainbow.easytier

import android.content.Intent
import android.os.Build
import android.os.Bundle
class MainActivity : TauriActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        initService()
    }

    private fun initService() {
        val serviceIntent = Intent(this, MainForegroundService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }
    }
}
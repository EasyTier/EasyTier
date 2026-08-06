package com.kkrainbow.easytier

import android.content.Intent
import android.os.Bundle

class MainActivity : TauriActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }
}

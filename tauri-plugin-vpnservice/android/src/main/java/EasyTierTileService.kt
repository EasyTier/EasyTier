package com.plugin.vpnservice

import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import java.lang.ref.WeakReference

class EasyTierTileService : TileService() {
    companion object {
        private const val PREFS_NAME = "easytier_quick_settings"
        private const val LAST_ERROR = "last_error"
        private val mainHandler = Handler(Looper.getMainLooper())

        @Volatile
        private var listeningService: WeakReference<EasyTierTileService>? = null

        fun refreshVpnState(context: Context) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .remove(LAST_ERROR)
                .apply()
            notifyStateChanged(context)
        }

        fun setLastError(context: Context, error: String) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(LAST_ERROR, error)
                .apply()
            notifyStateChanged(context)
        }

        private fun notifyStateChanged(context: Context) {
            listeningService?.get()?.let { service ->
                mainHandler.post {
                    if (listeningService?.get() === service) {
                        service.refreshTile()
                    }
                }
            }
            requestListeningState(
                context,
                ComponentName(context, EasyTierTileService::class.java),
            )
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        listeningService = WeakReference(this)
        refreshTile()
    }

    override fun onStopListening() {
        if (listeningService?.get() === this) {
            listeningService = null
        }
        super.onStopListening()
    }

    override fun onDestroy() {
        if (listeningService?.get() === this) {
            listeningService = null
        }
        super.onDestroy()
    }

    private fun refreshTile() {
        val active = TauriVpnService.self?.isVpnActive() == true
        updateTile(active)
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) {
            unlockAndRun { handleClick() }
        } else {
            handleClick()
        }
    }

    private fun handleClick() {
        val requestedActive = isRequestedActive()
        val action = if (requestedActive) {
            TauriVpnService.ACTION_STOP
        } else {
            TauriVpnService.ACTION_START_HEADLESS
        }
        ContextCompat.startForegroundService(
            this,
            TauriVpnService.createIntent(this, action),
        )
    }

    private fun updateTile(active: Boolean) {
        qsTile?.apply {
            val desiredActive = isRequestedActive()
            state = if (active || desiredActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val error = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .getString(LAST_ERROR, null)
                subtitle = if (active) {
                    "Connected"
                } else if (desiredActive) {
                    "Connecting…"
                } else {
                    error ?: if (TauriVpnService.hasHeadlessProfile(this@EasyTierTileService)) {
                        "Disconnected"
                    } else {
                        "Open EasyTier once"
                    }
                }
            }
            updateTile()
        }
    }

    private fun isRequestedActive(): Boolean =
        TauriVpnService.self?.isVpnRequestedOrActive() == true
}

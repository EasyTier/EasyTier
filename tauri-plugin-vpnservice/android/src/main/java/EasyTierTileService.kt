package com.plugin.vpnservice

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat

class EasyTierTileService : TileService() {
    companion object {
        private const val PREFS_NAME = "easytier_quick_settings"
        private const val LAST_ERROR = "last_error"

        fun setVpnActive(context: Context, active: Boolean) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean("vpn_active", active)
                .remove(LAST_ERROR)
                .apply()
            requestListeningState(
                context,
                ComponentName(context, EasyTierTileService::class.java),
            )
        }

        fun setLastError(context: Context, error: String) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean("vpn_active", false)
                .putString(LAST_ERROR, error)
                .apply()
            requestListeningState(
                context,
                ComponentName(context, EasyTierTileService::class.java),
            )
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        val active = TauriVpnService.self?.isVpnActive()
            ?: getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean("vpn_active", false)
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
        val active = TauriVpnService.self?.isVpnActive()
            ?: getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean("vpn_active", false)
        val action = if (active) {
            TauriVpnService.ACTION_STOP
        } else {
            TauriVpnService.ACTION_START_HEADLESS
        }
        ContextCompat.startForegroundService(
            this,
            Intent(this, TauriVpnService::class.java).setAction(action),
        )
    }

    private fun updateTile(active: Boolean) {
        qsTile?.apply {
            state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val error = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .getString(LAST_ERROR, null)
                subtitle = if (active) "Connected" else error ?: if (
                    TauriVpnService.hasHeadlessProfile(this@EasyTierTileService)
                ) "Disconnected" else "Open EasyTier once"
            }
            updateTile()
        }
    }
}

package com.plugin.vpnservice

import android.app.Activity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import app.tauri.plugin.Invoke

@InvokeArg
class PingArgs {
  var value: String? = null
}

@TauriPlugin
class VpnServicePlugin(private val activity: Activity): Plugin(activity) {
    private val implementation = Example()

    @Command
    fun ping(invoke: Invoke) {
        val args = invoke.parseArgs(PingArgs::class.java)

        val ret = JSObject()
        ret.put("value", implementation.pong(args.value ?: "default value :("))
        invoke.resolve(ret)
    }

    @Command
    fun startVpn(invoke: Invoke) {
        val it = VpnService.prepare(activity);
        var fd: Int = 0
        if (it != null) {
            var ret = activity.startActivityForResult(it, 0x0f)
            println("OOOOOOOOO $it")
        } else {
            startVpn()
        }
        trigger("vpn-started", JSObject())
        invoke.resolve(JSObject())
    }

    private fun startVpn() {
        activity.startService(Intent(activity, TauriVpnService::class.java, ))
    }

}

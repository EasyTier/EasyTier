package com.plugin.vpnservice

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import android.webkit.WebView

@InvokeArg
class PingArgs {
    var value: String? = null
}

@InvokeArg
class StartVpnArgs {
    var ipv4Addr: String? = null
    var routes: Array<String> = emptyArray()
    var dns: String? = null
    var disallowedApplications: Array<String> = emptyArray()
    var mtu: Int? = null
}

@TauriPlugin
class VpnServicePlugin(private val activity: Activity) : Plugin(activity) {
    private val implementation = Example()

    override fun load(webView: WebView) {
        println("load vpn service plugin")
        TauriVpnService.triggerCallback = { event, data ->
            println("vpn: triggerCallback $event $data")
            trigger(event, data)
        }
    }

    @Command
    fun ping(invoke: Invoke) {
        val args = invoke.parseArgs(PingArgs::class.java)

        val ret = JSObject()
        ret.put("value", implementation.pong(args.value ?: "default value :("))
        invoke.resolve(ret)
    }

    @Command
    fun prepareVpn(invoke: Invoke) {
        println("prepare vpn in plugin")
        val it = VpnService.prepare(activity)
        var ret = JSObject()
        if (it != null) {
            activity.startActivityForResult(it, 0x0f)
            ret.put("errorMsg", "again")
        }
        invoke.resolve(ret)
    }

    @Command
    fun startVpn(invoke: Invoke) {
        val args = invoke.parseArgs(StartVpnArgs::class.java)
        println("start vpn in plugin, args: $args")

        TauriVpnService.self?.onRevoke()

        val it = VpnService.prepare(activity)
        var ret = JSObject()
        if (it != null) {
            ret.put("errorMsg", "need_prepare")
        } else {
            var intent = Intent(activity, TauriVpnService::class.java)
            intent.putExtra(TauriVpnService.IPV4_ADDR, args.ipv4Addr)
            intent.putExtra(TauriVpnService.ROUTES, args.routes)
            intent.putExtra(TauriVpnService.DNS, args.dns)
            intent.putExtra(TauriVpnService.DISALLOWED_APPLICATIONS, args.disallowedApplications)
            intent.putExtra(TauriVpnService.MTU, args.mtu)

            activity.startService(intent)
        }
        invoke.resolve(ret)
    }

    @Command
    fun stopVpn(invoke: Invoke) {
        println("stop vpn in plugin")
        TauriVpnService.self?.onRevoke()
        activity.stopService(Intent(activity, TauriVpnService::class.java))
        println("stop vpn in plugin end")
        invoke.resolve(JSObject())
    }
}

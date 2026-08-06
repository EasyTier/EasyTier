package com.plugin.vpnservice

object HeadlessEasyTierBridge {
    init {
        System.loadLibrary("app_lib")
    }

    @JvmStatic external fun start(configToml: String): String
    @JvmStatic external fun stop(instanceId: String): String
    @JvmStatic external fun attachTunFd(instanceId: String, fd: Int): String
}

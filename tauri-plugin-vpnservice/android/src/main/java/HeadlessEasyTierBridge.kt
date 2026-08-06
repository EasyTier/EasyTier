package com.plugin.vpnservice

object HeadlessEasyTierBridge {
    init {
        System.loadLibrary("app_lib")
    }

    @JvmStatic external fun start(configToml: String): String
    @JvmStatic external fun stop(): String
    @JvmStatic external fun attachTunFd(fd: Int): String
}

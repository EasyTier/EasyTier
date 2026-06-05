package com.easytier.jni

fun interface ConfigServerEventCallback {
    fun onEvent(eventJson: String)
}

/** EasyTier JNI 接口类 提供 Android 应用调用 EasyTier 网络功能的接口 */
object EasyTierJNI {

    init {
        // 加载本地库
        System.loadLibrary("easytier_android_jni")
    }

    /**
     * 设置 TUN 文件描述符
     * @param instanceName 实例名称
     * @param fd TUN 文件描述符
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic external fun setTunFd(instanceName: String, fd: Int): Int

    /**
     * 解析配置字符串
     * @param config TOML 格式的配置字符串
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当配置解析失败时抛出异常
     */
    @JvmStatic external fun parseConfig(config: String): Int

    /**
     * 运行网络实例
     * @param config TOML 格式的配置字符串
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当实例启动失败时抛出异常
     */
    @JvmStatic external fun runNetworkInstance(config: String): Int

    /**
     * 启动配置服务器客户端
     * @param url 配置服务器 URL
     * @param hostname 主机名，传入 null 使用系统主机名
     * @param machineId 稳定机器 ID，由调用方负责持久化
     * @param secureMode 是否启用 secure mode
     * @param callback 远程配置应用/删除事件回调
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当客户端启动失败时抛出异常
     */
    @JvmStatic
    external fun startConfigServerClient(
            url: String,
            hostname: String?,
            machineId: String,
            secureMode: Boolean,
            callback: ConfigServerEventCallback?
    ): Int

    /**
     * 停止配置服务器客户端
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当客户端停止失败时抛出异常
     */
    @JvmStatic external fun stopConfigServerClient(): Int

    /** 查询配置服务器客户端是否已连接 */
    @JvmStatic external fun isConfigServerClientConnected(): Boolean

    /**
     * 保留指定的网络实例，停止其他实例
     * @param instanceNames 要保留的实例名称数组，传入 null 或空数组将停止所有实例
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic external fun retainNetworkInstance(instanceNames: Array<String>?): Int

    /**
     * 收集网络信息
     * @param maxLength 最大返回条目数
     * @return 包含网络信息的 JSON 字符串
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic external fun collectNetworkInfos(maxLength: Int): String?

    /**
     * 获取最后的错误消息
     * @return 错误消息字符串，如果没有错误则返回 null
     */
    @JvmStatic external fun getLastError(): String?

    /**
     * 便利方法：停止所有网络实例
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic
    fun stopAllInstances(): Int {
        return retainNetworkInstance(null)
    }

    /**
     * 便利方法：停止指定实例外的所有实例
     * @param instanceName 要保留的实例名称
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic
    fun retainSingleInstance(instanceName: String): Int {
        return retainNetworkInstance(arrayOf(instanceName))
    }
}

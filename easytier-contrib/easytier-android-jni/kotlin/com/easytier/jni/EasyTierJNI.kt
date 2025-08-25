package com.easytier.jni

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
     * 保留指定的网络实例，停止其他实例
     * @param instanceNames 要保留的实例名称数组，传入 null 或空数组将停止所有实例
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic external fun retainNetworkInstance(instanceNames: Array<String>?): Int

    /**
     * 收集网络信息
     * @param maxLength 最大返回条目数
     * @return 包含网络信息的字符串数组，每个元素格式为 "key=value"
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

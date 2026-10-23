# 使用说明

1. 需要将 proto 文件放入 app/src/main/proto
2. android/gradle/libs.versions.toml 中加入依赖

```
# Wire 核心运行时
android-wire-runtime = { group = "com.squareup.wire", name = "wire-runtime", version = "5.3.11" }
moshi = { module = "com.squareup.moshi:moshi", version.ref = "moshi" }
android-wire-moshi-adapter = { group = "com.squareup.wire", name = "wire-moshi-adapter", version = "5.3.11" }
kotlinx-serialization-json = { group = "org.jetbrains.kotlinx", name = "kotlinx-serialization-json", version = "1.9.0" }
```

3. build.gradle.kts 中加入

```
plugins {
    ...
    alias(libs.plugins.wire)
}

dependencies {
    ...
    implementation(libs.android.wire.runtime)
    implementation(libs.android.wire.moshi.adapter)
    implementation(libs.moshi)
}

...

wire {
    kotlin {
        rpcRole = "none"
    }
}
```

4. 调用 easytier-contrib/easytier-android-jni/build.sh 生成 jni 和 ffi 的 so 文件及 rustls-platform-verifier.aar。
将 so 文件放到 android/app/src/main/jniLibs/arm64-v8a，AAR 放到 android/app/libs，并在 app 的 Gradle 文件中加入：

```
dependencies {
    implementation(files("libs/rustls-platform-verifier.aar"))
}
```

若启用代码压缩，还需在 ProGuard 规则中加入：

```
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }
```

5. 使用 EasyTierManager 可以拉起 EasyTier 实例并启动 Android VpnService 组件。
它会在启动实例前初始化 Android 证书校验器。直接调用 EasyTierJNI.runNetworkInstance
或 EasyTierJNI.startConfigServerClient 的应用，须先调用
`EasyTierJNI.initializeCertificateVerifier(applicationContext)`。

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

4. 调用 easytier-contrib/easytier-android-jni/build.sh 生成 jni 和 ffi 的 so 文件。
并将生成的 so 文件放到 android/app/src/main/jniLibs/arm64-v8a 目录下。

5. 使用 EasyTierManager 可以拉起 EasyTier 实例并启动 Android VpnService 组件。
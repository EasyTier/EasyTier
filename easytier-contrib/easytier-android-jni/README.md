# EasyTier Android JNI

这是 EasyTier 的 Android JNI 绑定库，允许 Android 应用程序调用 EasyTier 的网络功能。

## 功能特性

- 🚀 完整的 EasyTier FFI 接口封装
- 📱 原生 Android JNI 支持
- 🔧 支持多种 Android 架构 (arm64-v8a, armeabi-v7a, x86, x86_64)
- 🛡️ 类型安全的 Java 接口
- 📝 详细的错误处理和日志记录

## 支持的架构

- `arm64-v8a` (aarch64-linux-android)
- `armeabi-v7a` (armv7-linux-androideabi)
- `x86` (i686-linux-android)
- `x86_64` (x86_64-linux-android)

## 构建要求

### 系统要求

- Rust 1.70+
- Android NDK r21+
- Linux/macOS 开发环境

### 环境设置

1. **安装 Rust**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

2. **安装 Android NDK**
   - 下载 Android NDK: https://developer.android.com/ndk/downloads
   - 解压到合适的目录
   - 设置环境变量:
     ```bash
     export ANDROID_NDK_ROOT=/path/to/android-ndk
     ```

3. **添加 Android 目标**
   ```bash
   rustup target add aarch64-linux-android
   rustup target add armv7-linux-androideabi
   rustup target add i686-linux-android
   rustup target add x86_64-linux-android
   ```

## 构建步骤

1. **克隆项目并进入目录**
   ```bash
   cd /path/to/EasyTier/easytier-contrib/easytier-android-jni
   ```

2. **运行构建脚本**
   ```bash
   ./build.sh
   ```

3. **构建完成后，库文件将生成在 `target/android/` 目录下**
   ```
   target/android/
   ├── arm64-v8a/
   │   └── libeasytier_android_jni.so
   ├── armeabi-v7a/
   │   └── libeasytier_android_jni.so
   ├── x86/
   │   └── libeasytier_android_jni.so
   └── x86_64/
       └── libeasytier_android_jni.so
   ```

## Android 项目集成

### 1. 复制库文件

将生成的 `.so` 文件复制到您的 Android 项目中：

```
your-android-project/
└── src/main/
    ├── jniLibs/
    │   ├── arm64-v8a/
    │   │   └── libeasytier_android_jni.so
    │   ├── armeabi-v7a/
    │   │   └── libeasytier_android_jni.so
    │   ├── x86/
    │   │   └── libeasytier_android_jni.so
    │   └── x86_64/
    │       └── libeasytier_android_jni.so
    └── java/
        └── com/easytier/jni/
            └── EasyTierJNI.java
```

### 2. 复制 Java 接口

将 `java/com/easytier/jni/EasyTierJNI.java` 复制到您的 Android 项目的相应包路径下。

### 3. 添加权限

在 `AndroidManifest.xml` 中添加必要的权限：

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.CHANGE_NETWORK_STATE" />
```

## 使用示例

### 基本使用

```java
import com.easytier.jni.EasyTierJNI;
import java.util.Map;

public class EasyTierManager {
    
    // 初始化网络实例
    public void startNetwork() {
        String config = """
            inst_name = "my_instance"
            network = "my_network"
            """; 
        
        try {
            // 解析配置
            int result = EasyTierJNI.parseConfig(config);
            if (result != 0) {
                String error = EasyTierJNI.getLastError();
                throw new RuntimeException("配置解析失败: " + error);
            }
            
            // 启动网络实例
            result = EasyTierJNI.runNetworkInstance(config);
            if (result != 0) {
                String error = EasyTierJNI.getLastError();
                throw new RuntimeException("网络实例启动失败: " + error);
            }
            
            System.out.println("EasyTier 网络实例启动成功");
            
        } catch (RuntimeException e) {
            System.err.println("启动失败: " + e.getMessage());
        }
    }
    
    // 获取网络信息
    public void getNetworkInfo() {
        try {
            Map<String, String> infos = EasyTierJNI.collectNetworkInfosAsMap(10);
            for (Map.Entry<String, String> entry : infos.entrySet()) {
                System.out.println(entry.getKey() + ": " + entry.getValue());
            }
        } catch (RuntimeException e) {
            System.err.println("获取网络信息失败: " + e.getMessage());
        }
    }
    
    // 停止所有实例
    public void stopNetwork() {
        try {
            int result = EasyTierJNI.stopAllInstances();
            if (result == 0) {
                System.out.println("所有网络实例已停止");
            }
        } catch (RuntimeException e) {
            System.err.println("停止网络失败: " + e.getMessage());
        }
    }
}
```

### VPN 服务集成

如果您要在 Android VPN 服务中使用：

```java
public class EasyTierVpnService extends VpnService {
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // 建立 VPN 连接
        ParcelFileDescriptor vpnInterface = establishVpnInterface();
        
        if (vpnInterface != null) {
            int fd = vpnInterface.getFd();
            
            // 设置 TUN 文件描述符
            try {
                EasyTierJNI.setTunFd("my_instance", fd);
            } catch (RuntimeException e) {
                Log.e("EasyTier", "设置 TUN FD 失败", e);
            }
        }
        
        return START_STICKY;
    }
    
    private ParcelFileDescriptor establishVpnInterface() {
        Builder builder = new Builder();
        builder.setMtu(1500);
        builder.addAddress("10.0.0.2", 24);
        builder.addRoute("0.0.0.0", 0);
        builder.setSession("EasyTier VPN");
        
        return builder.establish();
    }
}
```

## API 参考

### EasyTierJNI 类方法

| 方法 | 描述 | 参数 | 返回值 |
|------|------|------|--------|
| `parseConfig(String config)` | 解析 TOML 配置 | config: 配置字符串 | 0=成功, -1=失败 |
| `runNetworkInstance(String config)` | 启动网络实例 | config: 配置字符串 | 0=成功, -1=失败 |
| `setTunFd(String instanceName, int fd)` | 设置 TUN 文件描述符 | instanceName: 实例名, fd: 文件描述符 | 0=成功, -1=失败 |
| `retainNetworkInstance(String[] names)` | 保留指定实例 | names: 实例名数组 | 0=成功, -1=失败 |
| `collectNetworkInfos(int maxLength)` | 收集网络信息 | maxLength: 最大条目数 | 信息字符串数组 |
| `collectNetworkInfosAsMap(int maxLength)` | 收集网络信息为 Map | maxLength: 最大条目数 | Map<String, String> |
| `getLastError()` | 获取最后错误 | 无 | 错误消息字符串 |
| `stopAllInstances()` | 停止所有实例 | 无 | 0=成功, -1=失败 |
| `retainSingleInstance(String name)` | 保留单个实例 | name: 实例名 | 0=成功, -1=失败 |

## 故障排除

### 常见问题

1. **构建失败: "Android NDK not found"**
   - 确保设置了 `ANDROID_NDK_ROOT` 环境变量
   - 检查 NDK 路径是否正确

2. **运行时错误: "java.lang.UnsatisfiedLinkError"**
   - 确保 `.so` 文件放在正确的 `jniLibs` 目录下
   - 检查目标架构是否匹配

3. **配置解析失败**
   - 检查 TOML 配置格式是否正确
   - 使用 `getLastError()` 获取详细错误信息

### 调试技巧

- 启用 Android 日志查看 JNI 层的日志输出
- 使用 `adb logcat -s EasyTier-JNI` 查看相关日志
- 检查 `getLastError()` 返回的错误信息

## 许可证

本项目遵循与 EasyTier 主项目相同的许可证。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

## 相关链接

- [EasyTier 主项目](https://github.com/EasyTier/EasyTier)
- [Android NDK 文档](https://developer.android.com/ndk)
- [Rust JNI 文档](https://docs.rs/jni/)
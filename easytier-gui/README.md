# GUI for EasyTier

this is a GUI implementation for EasyTier, based on Tauri2.

## Compile

### Install prerequisites

```
apt install npm
npm install -g pnpm
```

### For Desktop (Win/Mac/Linux)

```
pnpm install
pnpm tauri build
```

### For Android

Need to install android SDK / emulator / NDK / Java (easy with android studio)

Setting up envs:
  - JAVA_HOME=D:\\Jrs\
  - NDK_HOME=D:\\Android\Sdk\ndk\27.0.11902837
  - ANDROID_HOME=D:\\Android\Sdk

Java version depend on gradle version specified in (easytier-gui\src-tauri\gen\android\build.gradle.kts)

See [Gradle compatibility matrix](https://docs.gradle.org/current/userguide/compatibility.html) for detail .

```
pnpm install
pnpm tauri android init
pnpm tauri android build
```
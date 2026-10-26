# GUI for EasyTier

this is a GUI implementation for EasyTier, based on Tauri2.

## Settings

Open **Settings** in the upper-right corner to manage desktop startup and window
behavior. Language, mode, configuration server, logs, About, and Exit are also
available there.

- **Launch at login** starts the GUI when you sign in to the operating system.
  This switch takes effect immediately, independently of Save or Cancel.
- **Minimize to tray on close** keeps the GUI and its networks running when you close the
  window. This is enabled by default. Disable it to exit when closing the window;
  use Exit to quit explicitly in either case.
- **Start a network automatically** lets you select a saved network in
  normal mode. Click Save to persist this choice and the close behavior. The GUI
  starts the selected network once after its initial connection is ready; it does
  not restart it on reconnect or if it is already running. A deleted selection
  produces an error rather than starting another network.

Enable both launch at login and automatic network startup to connect after signing
in. This does not replace service mode for running before login. Desktop startup
options are hidden on mobile platforms.

When trying a new executable, exit any existing GUI instance first. Launching a
second instance brings the existing instance to the foreground.

## Compile

### Install prerequisites

```
apt install npm
npm install -g pnpm
```

### For Desktop (Win/Mac/Linux)

```
cd ../tauri-plugin-vpnservice
pnpm install
pnpm build

cd ../easytier-web/frontend-lib
pnpm install
pnpm build

cd ../../easytier-gui
pnpm install
pnpm tauri build
```

### For Android

Need to install android SDK / emulator / NDK / Java (easy with android studio)

```
# For ArchLinux
sudo pacman -Sy sdkmanager
sudo sdkmanager --install platform-tools platforms\;android-34 ndk\;r26 build-tools
export PATH=/opt/android-sdk/platform-tools:$PATH
export ANDROID_HOME=/opt/android-sdk/
export NDK_HOME=/opt/android-sdk/ndk/26.0.10792818/
rustup target add aarch64-linux-android

install java 20
```

Java version depend on gradle version specified in (easytier-gui\src-tauri\gen\android\build.gradle.kts)

See [Gradle compatibility matrix](https://docs.gradle.org/current/userguide/compatibility.html) for detail .

```
pnpm install
pnpm tauri android init
pnpm tauri android build
```

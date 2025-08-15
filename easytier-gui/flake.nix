{
  # usage:
  # nix develop .#android --extra-experimental-features "nix-command flakes"
  # pnpm tauri android build
  description = "Android build environment for EasyTier";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # java21
    nixpkgs-java.url = "github:NixOS/nixpkgs/85dbfc7aaf52ecb755f87e577ddbe6dbbdbc1054";
    #nixpkgs-java.url = "github:NixOS/nixpkgs/nixos-unstable";
    # androidEnv
    nixpkgs-android.url =  "github:NixOS/nixpkgs/85dbfc7aaf52ecb755f87e577ddbe6dbbdbc1054";
    #nixpkgs-android.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, nixpkgs-java, nixpkgs-android, flake-utils, rust-overlay,  ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config = { licenseAccepted = true; allowUnfree = true; };
        };

        rustVersion = "1.89.0";
        rustWithAndroid = pkgs.rust-bin.stable.${rustVersion}.default.override {
            extensions = [ "rust-src" "rust-std" ];
            targets = [
             "aarch64-linux-android"
             "armv7-linux-androideabi"
             "i686-linux-android"
             "x86_64-linux-android"
            ];
        };
        includeAuto = pkgs.stdenv.hostPlatform.isx86_64 || pkgs.stdenv.hostPlatform.isDarwin;
        # ndkVersion = "28.1.13356709";
        ndkVersion = "26.1.10909125";
        ndkVersions = [
          ndkVersion
        ];

        # Android 环境配置
        sdkArgs = {
          includeNDK = true;
          includeSources = true;
          includeSystemImages = false;
          includeEmulator = false;
          inherit ndkVersions;
          useGoogleAPIs = true;
          useGoogleTVAddOns = true;
          buildToolsVersions = [ "34.0.0" ];

          # Make sure everything from the last decade works since we are not using system images.
          numLatestPlatformVersions = 10;
          includeExtras = [
            "extras;google;gcm"
          ]
          ++ pkgs.lib.optionals includeAuto [
            "extras;google;auto"
          ];
          # Accepting more licenses declaratively:
          extraLicenses = [
            # Already accepted for you with the global accept_license = true or
            # licenseAccepted = true on androidenv.
            # "android-sdk-license"

            # These aren't, but are useful for more uncommon setups.
            "android-sdk-preview-license"
            "android-googletv-license"
            "android-sdk-arm-dbt-license"
            "google-gdk-license"
            "intel-android-extra-license"
            "intel-android-sysimage-license"
            "mips-android-sysimage-license"
          ];
        };
        javaPkgs = import nixpkgs-java { inherit system; };
        androidEnv = pkgs.callPackage "${nixpkgs-android}/pkgs/development/mobile/androidenv" {
          inherit pkgs;
          licenseAccepted = true;
        };
        androidComposition = androidEnv.composeAndroidPackages sdkArgs;
        androidSdk = androidComposition.androidsdk;
        platformTools = androidComposition.platform-tools;
        cmake = androidComposition.cmake;
        # NDK uses a specific host tag directory name which we can determine from the host platform
        ndkHostTag = if pkgs.stdenv.isLinux then "linux-x86_64" else if pkgs.stdenv.isDarwin then "darwin-x86_64" else "";
        ndkToolchain = "${androidSdk}/libexec/android-sdk/ndk/${ndkVersion}/toolchains/llvm/prebuilt/${ndkHostTag}";
      in

      {
        # android entry
        devShells.android = pkgs.mkShell rec {
          nativeBuildInputs = [
              rustWithAndroid
              javaPkgs.jdk
              androidSdk
              platformTools
              cmake
              pkgs.glibc_multi.dev 
              # pkgs.clang
              pkgs.pkg-config
              pkgs.protobuf

              pkgs.nodejs_22
              pkgs.pnpm
            ];
           buildInputs = [];

          LANG = "C.UTF-8";
          LC_ALL = "C.UTF-8";
          JAVA_HOME = "${javaPkgs.jdk}/lib/openjdk";

          ANDROID_SDK_ROOT = "${androidSdk}/libexec/android-sdk";
          ANDROID_NDK_ROOT = "${ANDROID_SDK_ROOT}/ndk-bundle";
          NDK_HOME = "${androidSdk}/libexec/android-sdk/ndk/${ndkVersion}";

          LIBCLANG_PATH = "${ndkToolchain}/lib";
          KCP_SYS_EXTRA_HEADER_PATH = "${ndkToolchain}/lib/clang/19/include:${pkgs.glibc_multi.dev}/include";
          ZSTD_SYS_STATIC = "1";

          BINDGEN_EXTRA_CLANG_ARGS = "--sysroot=${ndkToolchain}/sysroot -I${ndkToolchain}/lib/clang/17/include ";
  
          # 设置编译器标志
          shellHook = ''
            echo "Android environment activated"
            export GRADLE_OPTS="-Dorg.gradle.project.android.aapt2FromMavenOverride=$(echo "$ANDROID_SDK_ROOT/build-tools/"*"/aapt2")"
            cmake_root="$(echo "$ANDROID_SDK_ROOT/cmake/"*/)"
            export PATH="$cmake_root/bin:$PATH"

            unset NIX_CFLAGS_COMPILE
            unset NIX_CFLAGS_COMPILE_FOR_BUILD
  
            cat <<EOF > local.properties
            sdk.dir=$ANDROID_SDK_ROOT
            ndk.dir=$ANDROID_NDK_ROOT
            cmake.dir=$cmake_root
            EOF
          '';
        };

        #devShells.default = pkgs.mkShell {};
      }
    );
}

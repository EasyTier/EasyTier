{
  description = "EasyTier development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config = {
            licenseAccepted = true;
            allowUnfree = true;
          };
        };
        rustVersion = "1.89.0";
        makeRust =
          features:
          let
            rustTarget = pkgs.stdenv.hostPlatform.config;
            muslTarget = pkgs.lib.replaceStrings [ "gnu" ] [ "musl" ] rustTarget;
            muslTargets = if pkgs.stdenv.isLinux then [ muslTarget ] else [ ];
          in
          pkgs.rust-bin.stable.${rustVersion}.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ]
            ++ (if builtins.elem "android" features then android.rust.extensions else [ ]);

            targets = muslTargets ++ (if builtins.elem "android" features then android.rust.targets else []);
          };

        android = import ./android.nix {
          inherit pkgs system nixpkgs;
        };

        makeShell =
          features:
          let
            hasFeature = feature: builtins.elem feature features;
            withFeature = feature: pkgList: if hasFeature feature then pkgList else [ ];
            flattenPaths = xs: builtins.concatLists (map (p: if builtins.isList p then p else [ p ]) xs);
            rust = makeRust features;
          in
          pkgs.mkShell (rec {
            nativeBuildInputs =
              with pkgs;
              (
                [
                  rust
                  protobuf
                  clang
                  pkg-config
                  bridge-utils # for three node test
                ]
                ++ (withFeature "web" [
                  nodejs_22
                  pnpm
                ])
                ++ (withFeature "gui" [
                  libayatana-appindicator
                ])
                ++ (withFeature "android" android.packages)
              );

            buildInputs = with pkgs; ([
              jemalloc
              zstd
              openssl
              libclang
              llvmPackages.libclang
              libsoup_3
              webkitgtk_4_1
            ]);

            RUST_SRC_PATH = "${rust}/lib/rustlib/src/rust/library";
            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
            BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.clang}/resource-root/include";
            LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (flattenPaths (buildInputs ++ nativeBuildInputs));
            ZSTD_SYS_USE_PKG_CONFIG = true;
            KCP_SYS_EXTRA_HEADER_PATH = "${pkgs.libclang.lib}/lib/clang/19/include:${pkgs.glibc.dev}/include";
            JEMALLOC_OVERRIDE = "${pkgs.jemalloc}/lib/libjemalloc.so";
          }
          // (if hasFeature "android" then android.envVars else { }));
      in
      {
        devShells = {
          default = makeShell [ ];
          core = makeShell [ ];
          web = makeShell [ "web" ];
          gui = makeShell [ "gui" "web" ];
          android = makeShell [
            "android"
            "web"
          ];
          full = makeShell [
            "web"
            "gui"
            "android"
          ];
        };
      }
    );
}

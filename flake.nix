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

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustVersion = "1.87.0";
        rust = pkgs.rust-bin.stable.${rustVersion}.default.override{
          extensions = [ "rust-src" "rust-analyzer" ];
        };
      in
      {
        devShells.default = pkgs.mkShell rec {
          nativeBuildInputs = with pkgs; [
            rust
            protobuf
            clang
            pkg-config

            # web
            nodejs_22
            pnpm
          ];
          buildInputs = with pkgs; [
            zstd
            openssl
            libclang
            llvmPackages.libclang

            # gui
            webkitgtk_4_1
            libsoup_3
          ];

          RUST_SRC_PATH = "${rust}/lib/rustlib/src/rust/library";
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.clang}/resource-root/include";
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (buildInputs ++ nativeBuildInputs);
          ZSTD_SYS_USE_PKG_CONFIG = true;
          KCP_SYS_EXTRA_HEADER_PATH = "${pkgs.libclang.lib}/lib/clang/19/include:${pkgs.glibc.dev}/include";
        };
      }
    );
}

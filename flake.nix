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

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        lib = nixpkgs.lib;

        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rust
            pkg-config
            protobuf
          ];

          buildInputs = with pkgs; [
            zstd
          ];

          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          ZSTD_SYS_USE_PKG_CONFIG = true;
          KCP_SYS_EXTRA_HEADER_PATH = "${pkgs.libclang.lib}/lib/clang/19/include:${pkgs.glibc.dev}/include";
        };
      });
}

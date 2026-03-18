{
  description = "tapkey - derive keys from passkeys";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        isDarwin = pkgs.stdenv.isDarwin;
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "tapkey";
          version = "1.2.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          # Only build the CLI crate; macos/ requires Swift and Apple SDKs.
          buildAndTestSubdir = "cli";
          cargoBuildFlags = [ "-p" "tapkey" "--no-default-features" ];
          doCheck = false;
          # Exclude macos crate from workspace (its build.rs needs Swift/Xcode)
          postPatch = ''
            sed -i 's|members = \["core", "cli", "macos"\]|members = ["core", "cli"]|' Cargo.toml
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            age
            gh
            rustc
            cargo
            rustfmt
            clippy
            nodePackages.wrangler
          ];

          shellHook = if isDarwin then ''
            export PATH="/usr/bin:$PATH"
            unset SDKROOT DEVELOPER_DIR
          '' else "";
        };
      });
}

{
  description = "tapkey - derive keys from iCloud Keychain passkeys via Touch ID";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            age
            gh
            rustc
            cargo
            wasm-pack
            rustfmt
            clippy
          ];

          shellHook = ''
            echo "tapkey dev shell"
            echo "  make build       - build macOS app"
            echo "  make build-wasm  - build WASM package (Rust)"
            echo "  make test        - run all tests"
            echo "  make install     - build, sign, and symlink to ~/.local/bin"
          '';
        };
      });
}

{
  description = "tapkey - derive keys from iCloud Keychain passkeys via Touch ID";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "aarch64-darwin" "x86_64-darwin" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            age
            gh
          ];

          shellHook = ''
            echo "tapkey dev shell"
            echo "  make        - build and sign"
            echo "  make test   - run tests"
            echo "  make install - build, sign, and symlink to ~/.local/bin"
          '';
        };
      });
}

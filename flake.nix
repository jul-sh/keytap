{
  description = "prf-cli - derive keys from passkeys via WebAuthn PRF";

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
            age
            gh
          ];

          shellHook = ''
            echo "prf-cli dev shell"
            echo "  make install - build, sign, and symlink to ~/.local/bin"
          '';
        };
      });
}

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
            age
            gh
            rustc
            cargo
            rustfmt
            clippy
            nodePackages.wrangler
          ];

          # Ensure system Swift (from Xcode) is available — nix Swift
          # lacks the macOS 15 SDK needed for AuthenticationServices PRF.
          shellHook = ''
            export PATH="/usr/bin:$PATH"
            unset SDKROOT DEVELOPER_DIR
            echo "tapkey dev shell"
            echo "  make build   - build macOS app"
            echo "  make test    - run tests"
            echo "  make install - build, sign, and symlink to ~/.local/bin"
          '';
        };
      });
}

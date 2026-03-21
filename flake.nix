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

        # Pre-built release binaries (built in CI with attestation)
        # Updated automatically by the release workflow
        releases = {
          aarch64-darwin = {
            url = "https://github.com/jul-sh/tapkey/releases/download/v2.0.0/tapkey-v2.0.0-arm64.zip";
            hash = "sha256-qG7v9NocPNP40EW97KCgN+4mWmo2f2LB61pJQ2mvRis=";
          };
          x86_64-linux = {
            url = "https://github.com/jul-sh/tapkey/releases/download/v2.0.0/tapkey-v2.0.0-linux-x86_64.zip";
            hash = "sha256-8D3fJpUeH6dSMFe/mFi6Ul6sfr4X0oEt9lHKYJWirTY=";
          };
        };
      in
      {
        packages = pkgs.lib.optionalAttrs (builtins.hasAttr system releases) {
          default = pkgs.stdenv.mkDerivation {
            pname = "tapkey";
            version = "2.1.0";
            src = pkgs.fetchurl {
              inherit (releases.${system}) url hash;
            };
            sourceRoot = ".";
            nativeBuildInputs = [ pkgs.unzip ];
            unpackPhase = "unzip $src";
            installPhase = if isDarwin then ''
              mkdir -p $out/share/tapkey $out/bin
              cp -R Tapkey.app $out/share/tapkey/
              ln -s $out/share/tapkey/Tapkey.app/Contents/MacOS/tapkey $out/bin/tapkey
            '' else ''
              mkdir -p $out/bin
              cp tapkey $out/bin/tapkey
              chmod +x $out/bin/tapkey
            '';
          };
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

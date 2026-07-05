{
  description = "keytap - derive keys from passkeys";

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
            url = "https://github.com/jul-sh/keytap/releases/download/v4.2.0/keytap-v4.2.0-arm64.zip";
            hash = "sha256-Ns9GU3AY6lPpgps3WeT570rQQ1FkS3K7VmlHVBR0REM=";
          };
          x86_64-linux = {
            url = "https://github.com/jul-sh/keytap/releases/download/v4.2.0/keytap-v4.2.0-linux-x86_64.zip";
            hash = "sha256-FmSCBilJ4axesLOa/rGC1S4um1/bIoJfepAm0fssrgg=";
          };
        };
      in
      {
        packages = pkgs.lib.optionalAttrs (builtins.hasAttr system releases) {
          default = pkgs.stdenv.mkDerivation {
            pname = "keytap";
            version = "4.2.1";
            src = pkgs.fetchurl {
              inherit (releases.${system}) url hash;
            };
            sourceRoot = ".";
            nativeBuildInputs = [ pkgs.unzip ];
            unpackPhase = "unzip $src";
            installPhase = if isDarwin then ''
              mkdir -p $out/share/keytap $out/bin
              cp -R Keytap.app $out/share/keytap/
              ln -s $out/share/keytap/Keytap.app/Contents/MacOS/keytap $out/bin/keytap
            '' else ''
              mkdir -p $out/bin
              cp keytap $out/bin/keytap
              chmod +x $out/bin/keytap
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
            lld
            wasm-pack
            nodePackages.wrangler
          ];

          shellHook = if isDarwin then ''
            export PATH="/usr/bin:$PATH"
            unset SDKROOT DEVELOPER_DIR
          '' else "";
        };
      });
}

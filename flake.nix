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
            url = "https://github.com/jul-sh/keytap/releases/download/v4.1.1/keytap-v4.1.1-arm64.zip";
            hash = "sha256-z9Co8kch0I5lFnQBrcyuWW0xq/Rtk3UBOr8TZV1C1YM=";
          };
          x86_64-linux = {
            url = "https://github.com/jul-sh/keytap/releases/download/v4.1.1/keytap-v4.1.1-linux-x86_64.zip";
            hash = "sha256-lu3ARvbFJT6J42C6MNvvo/+6/SzEfq0ySuzhH8nC0Vg=";
          };
        };
      in
      {
        packages = pkgs.lib.optionalAttrs (builtins.hasAttr system releases) {
          default = pkgs.stdenv.mkDerivation {
            pname = "keytap";
            version = "4.1.1";
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

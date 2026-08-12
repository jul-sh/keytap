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
        macosLauncher = pkgs.writeShellScript "keytap-launcher" (
          builtins.readFile ./distribution/keytap-launcher.sh
        );

        # Pre-built release binaries (built in CI with attestation)
        # Updated automatically by the release workflow
        releases = {
          aarch64-darwin = {
            url = "https://github.com/jul-sh/keytap/releases/download/0ca2372/keytap-0ca2372-arm64.zip";
            hash = "sha256-PKtTkm10J4AuEKx2xUUs5/RnG68UtBKKON8hd33Y3eU=";
          };
          x86_64-linux = {
            url = "https://github.com/jul-sh/keytap/releases/download/0ca2372/keytap-0ca2372-linux-x86_64.zip";
            hash = "sha256-Bl69cQnlTdFiQFte1kJaA6MUjGg4XMjhsuZIzW5gcyE=";
          };
        };
      in
      {
        packages = pkgs.lib.optionalAttrs (builtins.hasAttr system releases) {
          default = pkgs.stdenv.mkDerivation {
            pname = "keytap";
            version = "8.0.0";
            src = pkgs.fetchurl {
              inherit (releases.${system}) url hash;
            };
            sourceRoot = ".";
            nativeBuildInputs = [ pkgs.unzip ]
              ++ pkgs.lib.optionals isDarwin [ pkgs.makeWrapper ];
            unpackPhase = "unzip $src";
            installPhase = if isDarwin then ''
              mkdir -p $out/share/keytap $out/bin
              cp -R Keytap.app $out/share/keytap/
              makeWrapper ${macosLauncher} $out/bin/keytap \
                --set KEYTAP_APP_BUNDLE $out/share/keytap/Keytap.app
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
            nodejs
          ];

          shellHook = if isDarwin then ''
            export PATH="/usr/bin:$PATH"
            unset SDKROOT DEVELOPER_DIR
          '' else "";
        };
      });
}

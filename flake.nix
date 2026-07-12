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
            url = "https://github.com/jul-sh/keytap/releases/download/v6.4.0/keytap-v6.4.0-arm64.zip";
            hash = "sha256-wiTBujQuN15Wis/+h7sq7f3+1FYLcL7FBfeBJu6iP0M=";
          };
          x86_64-linux = {
            url = "https://github.com/jul-sh/keytap/releases/download/v6.4.0/keytap-v6.4.0-linux-x86_64.zip";
            hash = "sha256-R/kJYVpOO8YcBDzh4NAjRRH2C6yMjm6PqcGgxZrmf4o=";
          };
        };

        # The only version statement is the release tag inside the artifact
        # URL, so the package version can never drift from what it ships.
        versionFromUrl = url:
          builtins.head (builtins.match ".*/download/v([^/]+)/.*" url);
      in
      {
        packages = pkgs.lib.optionalAttrs (builtins.hasAttr system releases) {
          default = pkgs.stdenv.mkDerivation {
            pname = "keytap";
            version = versionFromUrl releases.${system}.url;
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
            wrangler
          ];

          shellHook = if isDarwin then ''
            export PATH="/usr/bin:$PATH"
            unset SDKROOT DEVELOPER_DIR
          '' else "";
        };
      });
}

{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };

      rustToolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
        extensions = ["rust-src"];
      };

      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

      shell-mcp-pkg = pkgs.rustPlatform.buildRustPackage {
        pname = cargoToml.package.name;
        version = cargoToml.package.version;
        src = self;

        cargoLock = {
          lockFile = ./Cargo.lock;
        };
      };
    in {
      packages.default = shell-mcp-pkg;

      apps.default = flake-utils.lib.mkApp {
        drv = shell-mcp-pkg;
      };

      devShells.default = pkgs.mkShell {
        buildInputs = [
          rustToolchain
        ];

        shellHook = ''
          export PS1="(env:shell-mcp) $PS1"
        '';
      };
    });
}

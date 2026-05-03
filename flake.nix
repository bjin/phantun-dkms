{
  description = "Phantun fake-TCP Linux kernel module";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        rec {
          phantun = pkgs.linuxPackages.callPackage ./nix/package.nix { };
          default = phantun;
        }
      );

      nixosModules = rec {
        phantun = import ./nix/nixos-module.nix;
        default = phantun;
      };

      formatter = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.writeShellApplication {
          name = "phantun-dkms-nixfmt";
          runtimeInputs = [ pkgs.nixfmt-rfc-style ];
          text = ''
            if [ "$#" -eq 0 ]; then
              set -- flake.nix nix/package.nix nix/nixos-module.nix
            fi

            exec nixfmt "$@"
          '';
        }
      );
    };
}

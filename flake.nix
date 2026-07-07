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
          virtme-ng = pkgs.callPackage ./nix/virtme-ng.nix {
            busybox-static = pkgs.pkgsStatic.busybox;
          };
          dkms = pkgs.callPackage ./nix/dkms.nix { };
          default = phantun;
        }
      );

      # Everything needed to run the virtme-ng/pytest integration suite on a
      # NixOS host (see TESTING.md). Guest-side commands resolve through the
      # host PATH, so the same closure serves both sides of the VM boundary.
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          selfPkgs = self.packages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              selfPkgs.virtme-ng
              selfPkgs.dkms

              # host-side test driver
              (pkgs.python3.withPackages (ps: [
                ps.pytest
                ps.black
              ]))
              pkgs.git
              pkgs.dpkg
              pkgs.patchelf
              pkgs.clang-tools # clang-format for ./format.sh

              # module build (host `make` and in-guest dkms build)
              pkgs.gnumake
              pkgs.gcc
              pkgs.autoconf
              pkgs.automake
              pkgs.libtool
              pkgs.pahole
              pkgs.kmod
              pkgs.file

              # guest-side data plane tools used by the tests
              pkgs.iproute2
              pkgs.nftables
              pkgs.iputils
              pkgs.wireguard-tools
              pkgs.wireguard-go
              pkgs.openssh
              pkgs.util-linux
            ];

            # Used by prepare-kernels.py to make the prebuilt kbuild host
            # tools inside Ubuntu linux-headers packages runnable on NixOS
            # (their ELF interpreter points at /lib64/ld-linux*, which is a
            # stub here).
            env = {
              PHANTUN_PATCHELF_INTERP = "${pkgs.stdenv.cc.bintools.dynamicLinker}";
              PHANTUN_PATCHELF_RPATH = pkgs.lib.makeLibraryPath [
                pkgs.stdenv.cc.cc.lib
                pkgs.glibc
                pkgs.elfutils
                pkgs.zlib
                pkgs.openssl
                pkgs.zstd
              ];
            };
          };
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
          runtimeInputs = [ pkgs.nixfmt ];
          text = ''
            if [ "$#" -eq 0 ]; then
              set -- flake.nix nix/package.nix nix/nixos-module.nix nix/virtme-ng.nix nix/dkms.nix
            fi

            exec nixfmt "$@"
          '';
        }
      );
    };
}

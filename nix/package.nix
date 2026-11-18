{
  lib,
  stdenv,
  autoreconfHook,
  kernel,
  kernelModuleMakeFlags ? [ ],
}:

let
  versionLine = lib.findFirst (lib.hasPrefix "PACKAGE_VERSION=") null (
    lib.splitString "\n" (builtins.readFile ../dkms.conf)
  );
  versionValue =
    if versionLine == null then
      throw "PACKAGE_VERSION not found in dkms.conf"
    else
      lib.removePrefix "PACKAGE_VERSION=" versionLine;
  version = lib.removeSuffix "\"" (lib.removePrefix "\"" versionValue);
  kdir = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build";
  root = toString ../.;
in
stdenv.mkDerivation {
  pname = "phantun";
  inherit version;

  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      let
        rel = lib.removePrefix "${root}/" (toString path);
      in
      (type == "directory" && rel == "src")
      || lib.elem rel [
        "autogen.sh"
        "configure.ac"
        "dkms.conf"
        "Kbuild"
        "LICENSE"
        "Makefile"
      ]
      || (lib.hasPrefix "src/" rel && (lib.hasSuffix ".c" rel || lib.hasSuffix ".h" rel));
  };

  nativeBuildInputs = [ autoreconfHook ] ++ kernel.moduleBuildDependencies;
  hardeningDisable = [ "pic" ];

  configureFlags = [ "--with-kernel=${kdir}" ];
  makeFlags = kernelModuleMakeFlags ++ [ "KDIR=${kdir}" ];

  # Install through kbuild so the kernel's strip, signing (nixpkgs' kmodigest
  # via kernelModuleMakeFlags, which also writes phantun.ko.cer), and
  # compression steps run; NixOS's module aggregator requires the .cer.
  installTargets = [ "modules_install" ];
  installFlags = [
    "INSTALL_MOD_PATH=${placeholder "out"}"
    "INSTALL_MOD_DIR=updates"
  ];

  meta = {
    description = "Kernel module re-implementation of phantun, transforming UDP streams into fake-TCP streams";
    homepage = "https://github.com/bjin/phantun-dkms";
    license = lib.licenses.gpl2Plus;
    platforms = lib.platforms.linux;
  };
}

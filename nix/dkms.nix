{
  lib,
  stdenv,
  fetchFromGitHub,
  makeBinaryWrapper,
  coreutils,
  diffutils,
  findutils,
  gawk,
  gnugrep,
  gnused,
  gnutar,
  gzip,
  kmod,
  util-linux,
  xz,
  zstd,
}:

stdenv.mkDerivation rec {
  pname = "dkms";
  version = "3.4.1";

  src = fetchFromGitHub {
    owner = "dell";
    repo = "dkms";
    rev = "v${version}";
    hash = "sha256-xFb0fbEANpKrxFPdpdD9drgoyuryy3pu1KTIWXcQR/I=";
  };

  nativeBuildInputs = [ makeBinaryWrapper ];

  # `make` renders dkms from dkms.in with these paths baked in. The
  # Makefile's install target insists on DESTDIR-prefixing everything, so
  # install the few artifacts we care about by hand.
  makeFlags = [
    "SBIN=${placeholder "out"}/bin"
    "LIBDIR=${placeholder "out"}/lib/dkms"
    "KCONF=${placeholder "out"}/etc/kernel"
    "MODDIR=/lib/modules"
  ];

  installPhase = ''
    runHook preInstall

    install -D -m 0755 dkms $out/bin/dkms
    install -D -m 0644 dkms_framework.conf $out/etc/dkms/framework.conf
    install -D -m 0644 dkms.8 $out/share/man/man8/dkms.8

    runHook postInstall
  '';

  # dkms is a bash script; make sure the tools it shells out to are found
  # even under a minimal guest PATH. The kernel toolchain (make/gcc) is
  # intentionally NOT pinned here: module builds must use the environment's
  # compiler so it can match the target kernel.
  postFixup = ''
    wrapProgram $out/bin/dkms \
      --prefix PATH : ${
        lib.makeBinPath [
          coreutils
          diffutils
          findutils
          gawk
          gnugrep
          gnused
          gnutar
          gzip
          kmod
          util-linux
          xz
          zstd
        ]
      }
  '';

  meta = {
    description = "Dynamic Kernel Module System";
    homepage = "https://github.com/dell/dkms";
    license = lib.licenses.gpl2Plus;
    mainProgram = "dkms";
  };
}

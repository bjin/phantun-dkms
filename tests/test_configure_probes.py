"""Kbuild feature probes run by configure."""

import shlex


def test_probe_results_ignore_werror(vm, project_info):
    """configure must give the same answers when the kernel builds with -Werror.

    Kernels built with CONFIG_WERROR=y (OpenWrt sets it) turn every warning in a
    probe's test module into a build failure, so a probe that merely warns
    reports "no" there while reporting "yes" on the CI kernels, which leave
    CONFIG_WERROR unset. Kbuild appends KCFLAGS from the environment, so
    -Werror there reproduces those kernels on any test kernel.
    """
    build_dir = "/tmp/phantun-configure-probes"
    kdir = f"/lib/modules/{vm.kernel_ver}/build"
    vm.run(
        f"rm -rf {build_dir} && mkdir -p {build_dir} && tar xzf {shlex.quote(str(project_info['tar_path']))} -C {build_dir}"
    )

    headers = {}
    for kcflags in ("", "-Werror"):
        vm.run(
            f"cd {build_dir} && KCFLAGS={shlex.quote(kcflags)} ./configure --with-kernel={kdir} >/dev/null"
            " || { cat config.log; exit 1; }"
        )
        headers[kcflags] = vm.run(["cat", f"{build_dir}/config.h"]).stdout

    assert headers["-Werror"] == headers[""], "configure probe results change under -Werror"

"""Kbuild feature probes run by configure."""

import re
import shlex

# Every probe includes <linux/module.h>; a module with nothing else isolates
# the kernel headers' own warnings from warnings in probe code.
HEADER_BASELINE_MODULE = '#include <linux/module.h>\n\nMODULE_LICENSE("GPL");\n'


def header_warning_demotions(vm, build_dir, kdir):
    """Return -Wno-error flags for warnings the kernel headers raise by themselves.

    The harness builds against each Ubuntu mainline kernel with the host gcc
    aliased to the gcc-N its Makefile names (see VM.start), so headers can warn
    under a compiler they were never built with: CI's gcc-14 ignores the
    __counted_by attribute that gcc-15-built kernels enable and warns in every
    translation unit. A CONFIG_WERROR kernel is warning-free with its own
    compiler, so only warnings from probe code may turn into errors here.
    """
    mod_dir = f"{build_dir}/werror-baseline"
    vm.run(f"mkdir -p {mod_dir} && echo 'obj-m := baseline.o' >{mod_dir}/Makefile")
    vm.run(f"cat >{mod_dir}/baseline.c", input=HEADER_BASELINE_MODULE)
    res = vm.run(f"make -C {kdir} M={mod_dir} KCFLAGS=-Werror modules 2>&1", check=False)
    # Leveled warnings print as [-Werror=name=]; -Wno-error takes the bare name.
    names = sorted(set(re.findall(r"\[-Werror=([\w-]+)=?\]", res.stdout)))
    return [f"-Wno-error={name}" for name in names]


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

    werror = " ".join(["-Werror", *header_warning_demotions(vm, build_dir, kdir)])
    headers = {}
    for kcflags in ("", werror):
        vm.run(
            f"cd {build_dir} && KCFLAGS={shlex.quote(kcflags)} ./configure --with-kernel={kdir} >/dev/null"
            " || { cat config.log; exit 1; }"
        )
        headers[kcflags] = vm.run(["cat", f"{build_dir}/config.h"]).stdout

    assert headers[werror] == headers[""], f"configure probe results change under KCFLAGS={werror!r}"

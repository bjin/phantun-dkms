#!/bin/sh
set -e

require_command()
{
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'Error: required formatter not found: %s\n' "$1" >&2
        exit 1
    fi
}

require_command black
require_command clang-format

black .
clang-format -i --style=file src/*.c src/*.h

if command -v nix >/dev/null 2>&1; then
    nix fmt
fi

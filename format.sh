#!/bin/sh
set -e

python -m black --no-cache .
clang-format -i --style=file src/*.c src/*.h

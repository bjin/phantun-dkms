#!/bin/sh
set -e

python -m black **/*.py
clang-format -i --style=file src/*.c src/*.h

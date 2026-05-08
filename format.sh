#!/bin/sh
set -e

python -m black .
clang-format -i --style=file src/*.c src/*.h

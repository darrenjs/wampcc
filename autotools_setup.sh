#!/bin/sh

echo "===== Autoconf setup script ====="

# check for libtool
command -v libtool >/dev/null 2>&1 || { \
    echo "warning! libtool not found ... configure stage might fail" >&2; \
}

test -d m4 || mkdir -p m4
test -e README || ln -snf README.md README

autoreconf -fiv

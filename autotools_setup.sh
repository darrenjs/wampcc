#!/bin/sh

cd `dirname "$0"`

echo "===== Autoconf setup script ====="

# placate autotools
ln -snf README.md README
ln -snf LICENSE COPYING

test -d || mkdir -p m4

autoreconf -fiv

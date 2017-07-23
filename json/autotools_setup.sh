#!/bin/sh

cd `dirname "$0"`

echo "===== Autoconf setup script ====="

# placate autotools
ln -snf README.md README
ln -snf LICENSE COPYING

test -d m4 || mkdir -p m4

autoreconf -fiv

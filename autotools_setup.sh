#!/usr/bin/env bash


echo "===== Autoconf setup script ====="

# placate autotools
ln -snf README.md README
ln -snf LICENSE COPYING
autoreconf -fiv
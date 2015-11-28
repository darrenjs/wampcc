#!/usr/bin/env bash

find . -name Makefile.in -exec rm -f '{}' \;

[ -d m4 ] && rm -rf m4

for f in depcomp missing INSTALL install-sh config.sub config.guess compile \
    config.h.in configure aclocal.m4 configure aclocal.m4 ltmain.sh ar-lib \
    autom4te.cache COPYING
do
    [ -d "$f" ] && rm -rf "$f"
    rm -f "$f"
done
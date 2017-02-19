#!/bin/sh

echo "===== Autoconf setup script ====="

# check for libtool
command -v libtool >/dev/null 2>&1 || { \
    echo "warning! libtool not found ... configure stage might fail" >&2; \
}

test -d m4 || mkdir -p m4
test -e README || ln -snf README.md README

# if we have a bundled jalson project, then setup that up also
if [ -e jalson/README.md ];
then
    (cd jalson && ln -snf README.md README)
    (cd jalson && mkdir -p m4)
else
   echo "!!!"
   echo "!!! WARNING: no jalson sub-project detected!!! "
   echo "!!!          wampcc requires jalson to build successfully; without it configure will fail. "
   echo "!!!          Try running fetch_prerequisites.sh script to download jalson."
   echo "!!!"
   exit
fi



autoreconf -fiv

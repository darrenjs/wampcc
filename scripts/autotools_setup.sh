#!/bin/sh

cd  `dirname "$0"`/..

echo "===== Autoconf setup script ====="


test -d m4 || mkdir -p m4
test -e README || ln -snf README.md README

# if we have a bundled jalson project, then setup that up also
if [ -e jalson/README.md ];
then
    (cd jalson && ln -snf README.md README)
    (cd jalson && mkdir -p m4)
fi

autoreconf -fiv

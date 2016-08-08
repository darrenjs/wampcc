#!/bin/sh

cd  `dirname "$0"`/..

echo "===== Autoconf setup script ====="


test -d m4 || mkdir -p m4

autoreconf -fiv

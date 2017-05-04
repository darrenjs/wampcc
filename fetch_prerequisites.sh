#!/usr/bin/env bash

##
## get msgpack-c
##

# Download repo head of msgpack-c, since the latest version, 2.1.1, has a bug in
# the decoding of msgpack buffers

mkdir -p external

zipfile=msgpack.master.zip
test -f $zipfile || wget https://github.com/msgpack/msgpack-c/archive/master.zip -O $zipfile

if [ -f ${zipfile} ]; then
    unzip -q -d external msgpack.master.zip
    mv external/msgpack-c-master external/msgpack-c
else
    echo failed to download msgpack ... please try manually
    exit
fi

#!/usr/bin/env bash


# if you are behind a firewall, set a proxy
#export http_proxy=http://your_ip_proxy:port/
#export https_proxy=$http_proxy

mkdir -p external

# get jalson
jalson_ver=1.3
echo '***' fetching jalson $jalson_ver '***'
echo
test -f jalson-${jalson_ver}.tar.gz && rm -f jalson-${jalson_ver}.tar.gz
wget https://github.com/darrenjs/jalson/archive/v${jalson_ver}.tar.gz  -O jalson-${jalson_ver}.tar.gz
jalson_tar=jalson-${jalson_ver}.tar.gz
if [ -f ${jalson_tar} ];
then
  tar xfz ${jalson_tar}
  if [ -d jalson-${jalson_ver} ]
  then
    test -d jalson && rm -fr jalson
    mv jalson-${jalson_ver} jalson
    (cd jalson && ln -snf ../external .)
  else
    echo failed to find the directory jalson-${jalson_ver}
  fi
else
  echo failed to download jalson ${jalson_ver}
fi


##
## msgpack
##

# Download repo head of msgpack-c, since the latest version, 2.1.1, has a bug in
# the decoding of msgpack buffers

zipfile=msgpack.master.zip
test -f $zipfile || wget https://github.com/msgpack/msgpack-c/archive/master.zip -O $zipfile

if [ -f ${zipfile} ]; then
    unzip -q -d external msgpack.master.zip
    mv external/msgpack-c-master external/msgpack-c
else
    echo failed to download msgpack ... please try manually
    exit
fi

#!/usr/bin/env bash

##
## if you are behind a firewall, set a proxy
##
##    export http_proxy=http://your_ip_proxy:port/
##    export https_proxy=$http_proxy
##

mkdir -p external

##
## websocketpp
##

websocketpp_ver=0.7.0
echo '***' fetching websocketpp_ver $websocketpp_ver '***'
echo
tarfile=websocketpp-${websocketpp_ver}.tar.gz
test -f $tarfile || wget https://github.com/zaphoyd/websocketpp/archive/${websocketpp_ver}.tar.gz  -O $tarfile

if [ -f ${tarfile} ]; then
    tar xfz  ${tarfile}   -C external --transform "s/^websocketpp-${websocketpp_ver}/websocketpp/"
else
  echo failed to download websocketpp ... please try manually
fi

##
## jalson
##

jalson_ver=1.3
echo '***' fetching jalson $jalson_ver '***'
echo
tarfile=jalson-${jalson_ver}.tar.gz
test -f $tarfile || wget https://github.com/darrenjs/jalson/archive/v${jalson_ver}.tar.gz -O $tarfile
if [ -f ${tarfile} ];
then
  tar xfz ${tarfile}
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

# Need version >= 2.1.2, because for 2.1.2 and earlier, it has a bug in the
# decoding of msgpack buffers
ver=2.1.2
echo '***' fetching msgpack $ver '***'
echo
zipfile=cpp-${ver}.tar.gz
url=https://github.com/msgpack/msgpack-c/archive/$zipfile
test -f $zipfile || wget $url

if [ -f ${zipfile} ]; then
    test -f external || mkdir -p external
    tar xfz  ${zipfile} -C external
    cd external && mv msgpack-c-cpp-${ver} msgpack-c
else
    echo failed to download msgpack ... please try manually
    exit
fi

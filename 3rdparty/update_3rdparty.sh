#!/usr/bin/env bash

##
## if you are behind a firewall, set a proxy
##
##    export http_proxy=http://your_ip_proxy:port/
##    export https_proxy=$http_proxy
##



##
## websocketpp
##

websocketpp_ver=0.7.0
echo '***' fetching websocketpp_ver $websocketpp_ver '***'
echo
tarfile=websocketpp-${websocketpp_ver}.tar.gz
test -f $tarfile || wget https://github.com/zaphoyd/websocketpp/archive/${websocketpp_ver}.tar.gz  -O $tarfile

if [ -f ${tarfile} ]; then
    tar xfz  ${tarfile}   --transform "s/^websocketpp-${websocketpp_ver}/websocketpp/"
else
  echo failed to download websocketpp ... please try manually
fi


##
## msgpack
##

# Need version >= 2.1.2, because for 2.1.2 and earlier, it has a bug in the
# decoding of msgpack buffers
ver=2.1.3
echo '***' fetching msgpack $ver '***'
echo
zipfile=cpp-${ver}.tar.gz
url=https://github.com/msgpack/msgpack-c/archive/$zipfile
test -f $zipfile || wget $url

if [ -f ${zipfile} ]; then
    tar xfz  ${zipfile}
    mv msgpack-c-cpp-${ver} msgpack-c
else
    echo failed to download msgpack ... please try manually
    exit
fi

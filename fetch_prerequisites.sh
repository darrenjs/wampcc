#!/usr/bin/env bash

##
## if you are behind a firewall, set a proxy
##
##    export http_proxy=http://your_ip_proxy:port/
##    export https_proxy=$http_proxy
##

mkdir -p external

# get msgpack-c (take repo head, until the new C++11 header-only approach has
# bugs fixed, doesn't work in version 2.1.1)


##
## msgpack-c
##
zipfile=msgpack.master.zip
test -f $zipfile || wget https://github.com/msgpack/msgpack-c/archive/master.zip -O $zipfile

if [ -f ${zipfile} ]; then
    unzip -q -d external msgpack.master.zip
    mv external/msgpack-c-master external/msgpack-c
else
    echo failed to download msgpack ... please try manually
fi

# !!! Use this section once msgpackc is released, need version > 2.1.1
# version=2.1.1
# tarfile=cpp-${version}.tar.gz
# echo '***' fetching msgpack-c $version '***'
# echo
#
# test -f $tarfile || wget https://github.com/msgpack/msgpack-c/archive/$tarfile
#
# if [ -f ${tarfile} ]; then
#     tar xfz ${tarfile}  -C external --transform "s/msgpack-c-cpp-${version}/msgpack-c-cpp/"
# else
#     echo failed to download ${tarfile} ... please try manually
# fi
# unset version tarfile

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
## get jalson
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
    ln -snf ../external jalson/external
  else
    echo failed to find the directory jalson-${jalson_ver}
  fi
else
  echo failed to download jalson ${jalson_ver}
fi

#!/usr/bin/env bash

##
## if you are behind a firewall, set a proxy
##
##    export http_proxy=http://your_ip_proxy:port/
##    export https_proxy=$http_proxy
##

# get msgpack-c
version=2.1.1
tarfile=cpp-${version}.tar.gz
echo '***' fetching msgpack-c $version '***'
echo

test -f $tarfile || wget https://github.com/msgpack/msgpack-c/archive/$tarfile

if [ -f ${tarfile} ]; then
    tar xfz ${tarfile}  -C external --transform "s/msgpack-c-cpp-${version}/msgpack-c-cpp/"
else
    echo failed to download ${tarfile} ... please try manually
fi
unset version tarfile


# get googletest
googletest_ver=1.8.0
echo '***' fetching GoogleTest $googletest_ver '***'
echo
test -f release-${googletest_ver}.tar.gz && rm -f release-${googletest_ver}.tar.gz
wget https://github.com/google/googletest/archive/release-${googletest_ver}.tar.gz
googletest_tar=release-${googletest_ver}.tar.gz
if [ -f ${googletest_tar} ];
then
  tar xfz ${googletest_tar}  -C external --transform "s/googletest-release-${googletest_ver}/googletest/"
else
  echo failed to download googletest ${googletest_ver} into googletest directory ... please try manually
fi


# get jalson
jalson_ver=1.0
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
  else
    echo failed to find the directory jalson-${jalson_ver}
  fi
else
  echo failed to download jalson ${jalson_ver}
fi

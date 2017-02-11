#!/usr/bin/env bash


# if you are behind a firewall, set a proxy
#export http_proxy=http://your_ip_proxy:port/
#export https_proxy=$http_proxy

# get googletest
googletest_ver=1.8.0
echo '***' Downloading GoogleTest $googletest_ver '***'
wget https://github.com/google/googletest/archive/release-${googletest_ver}.tar.gz
googletest_tar=release-${googletest_ver}.tar.gz
if [ -e ${googletest_tar} ];
then
  tar xfz ${googletest_tar}  -C external --transform "s/googletest-release-${googletest_ver}/googletest/"
  rm -f ${googletest_tar}
else
  echo failed to download googletest ${googletest_ver} into googletest directory ... please try manually
fi

#!/usr/bin/env bash

# wampcc maintainer utilty script, for performing a fresh checkout and build.
#

BASEDIR=/var/tmp/$(whoami)/wampcc_cmake
SOURCEDIR=$BASEDIR/src
BUILDDIR=$BASEDIR/build
INSTALLDIR=$BASEDIR/install

export LIBUV_HOME=/home/$(whoami)/opt/libuv-1.10.2
export JANSSON_HOME=/home/$(whoami)/opt/jansson-2.10

export CXX=/usr/bin/clang++-3.5
export CXXFLAGS="-O0 -g3"

unset LD_LIBRARY_PATH

#----- script body follows -----

# create base dir
test -d $BASEDIR && rm -rf $$BASEDIR
mkdir -p $BASEDIR $SOURCEDIR
cd $BASEDIR

# checkout master
cd $SOURCEDIR
git clone https://github.com/darrenjs/wampcc.git

## clean
cd $SOURCEDIR/wampcc
rm -rf jalson; rm -rf external/msgpack-c external/googletest *.gz

# obtain source code & generate configure script
./fetch_prerequisites.sh

# cmake source configuration

rm -rf ${BUILDDIR} ${INSTALLDIR}
mkdir ${BUILDDIR}
cd ${BUILDDIR}


cmake $SOURCEDIR/wampcc
make -j

## FAILURE AT THIS POINT -- JALSON PROJECT NEEDS TO BE BUILT

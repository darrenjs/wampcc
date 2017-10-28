#!/usr/bin/env bash

# wampcc maintainer utilty script, for performing a fresh checkout and build.
#

BASEDIR=/var/tmp/$(whoami)/wampcc_cmake
SOURCEDIR=$BASEDIR/src
BUILDDIR=$BASEDIR/build
INSTALLDIR=$BASEDIR/install

export LIBUV_HOME=/home/$(whoami)/opt/libuv-1.10.2
export JANSSON_HOME=/home/$(whoami)/opt/jansson-2.10

export CXX=clang++
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

# cmake source configuration

rm -rf ${BUILDDIR} ${INSTALLDIR}
mkdir ${BUILDDIR}
cd ${BUILDDIR}


cmake   -DLIBUV_DIR=$LIBUV_HOME -DJANSSON_DIR=$JANSSON_HOME -DCMAKE_INSTALL_PREFIX=$INSTALLDIR --verbose -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=$CXX  $SOURCEDIR/wampcc

make -j 4
make install

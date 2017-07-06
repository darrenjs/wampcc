#!/usr/bin/env bash

# wampcc maintainer utilty script, for performing a fresh checkout and build.

BASEDIR=/var/tmp/$(whoami)/wampcc_build_check_autotools
SOURCEDIR=$BASEDIR/src
BUILDDIR=$BASEDIR/build
INSTALLDIR=$BASEDIR/install

export LIBUV_HOME=/home/$(whoami)/opt/libuv-1.10.2
export JANSSON_HOME=/home/$(whoami)/opt/jansson-2.10

export CXX=`which g++`
#export CXX=`which clang++`

unset LD_LIBRARY_PATH

#----- script body follows -----

# create base dir
test -d $BASEDIR && rm -rf $BASEDIR
mkdir -p $BASEDIR $SOURCEDIR
cd $BASEDIR

# checkout master
cd $SOURCEDIR
git clone https://github.com/darrenjs/wampcc.git

## clean
cd $SOURCEDIR/wampcc
./autotools_clean.sh ; rm -rf jalson; rm -rf external/msgpack-c external/googletest *.gz

# obtain source code & generate configure script
./fetch_prerequisites.sh
./autotools_setup.sh

## build

rm -rf ${BUILDDIR} ${INSTALLDIR}
mkdir ${BUILDDIR}
cd ${BUILDDIR}

$SOURCEDIR/wampcc/configure --prefix=${INSTALLDIR} --with-jansson=$JANSSON_HOME --with-libuv=$LIBUV_HOME
#../src/wampcc/configure --prefix=${INSTALLDIR} --with-jansson=$JANSSON_HOME --with-libuv=$LIBUV_HOME

make -j || make
make install

# Now build examples against the installed version

export WAMPCC_HOME=$INSTALLDIR
export LD_LIBRARY_PATH=${WAMPCC_HOME}/lib:${JANSSON_HOME}/lib:${LIBUV_HOME}/lib

cd $SOURCEDIR/wampcc/examples
make
unset WAMPCC_HOME

# Now run tests

cd ${BUILDDIR}
make check
#
# Copyright (c) 2017 Darren Smith
#
# wampcc is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

AM_CXXFLAGS = -Wall -g3 -ggdb -std=c++11 -I$(top_srcdir)/include \
-I$(top_srcdir)/3rdparty/websocketpp -I$(top_srcdir)/3rdparty $(libuvinc)

AM_LDFLAGS=-lpthread

# for make dist
EXTRA_DIST=CMakeLists.txt

# Primary defination of our shared library to be created.  Notice the
# _LTLIBRARIES key: automake is looking specifically for this pattern and then
# generating make rules which will invoke libtool.
#
# The "lib_" prefix indicates that the named products are to be installed in
# the $(libdir) directory. If we want to build a library that does not get
# installed, then we should use the prefix "noinst_".
lib_LTLIBRARIES = libwampcc.la

# The "include_" prefix includes a list of headers to be installed.  The
# "nobase_" additional prefix means the directory names are copied too.
# nobase_include_HEADERS = wampcc/types.h wampcc/kernel.h wampcc/wamp_session.h	\
# wampcc/wamp_router.h wampcc/protocol.h wampcc/rawsocket_protocol.h				\
# wampcc/websocket_protocol.h wampcc/tcp_socket.h wampcc/data_model.h				\
# wampcc/error.h wampcc/wampcc.h wampcc/ssl_socket.h wampcc/version.h

# List the sources for an individual library
libwampcc_la_SOURCES = platform.cc websocketpp_impl.cc websocket_protocol.cc	\
ssl.cc ssl_socket.cc tcp_socket.cc wamp_session.cc wamp_router.cc event_loop.cc	\
io_loop.cc kernel.cc pubsub_man.cc rpc_man.cc utils.cc protocol.cc helper.cc	\
rawsocket_protocol.cc ../../3rdparty/http_parser/http_parser.c http_parser.cc	\
data_model.cc error.cc ../../3rdparty/apache/base64.c socket_address.cc

# Include compile and link flags for an individual library.
#
# Note that to link against a static library which is part of this project, we
# should refers to them with relative paths inside the build directory, for
# example, "../common/libcommon.la"
#
# Note also, because we are using libtool, we should only refer to other
# libtool libraries (*.la)
#
# <library_LIBADD> : extras libtool objects to add to library
#
#libexio_la_CPPFLAGS =
#libexio_la_LIBADD  = ../libcpp11/libcpp11.la -lpthread
libwampcc_la_LIBADD  =  -lpthread -lssl -lcrypto $(libuvlib)

# Note: version info for shared libraries is three number system, where the
# numbers represent: CURRENT : REVISION : AGE
#
# - CURRENT:  library version. Only change if API has changed.
# - REVISION: revision of current version. Incr. base on internal changes.
# - AGE: indicates compatibilty with previous version of the shlib.
#
libwampcc_la_LDFLAGS =  -version-info 5:0:0

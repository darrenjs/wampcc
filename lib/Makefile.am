AM_CPPFLAGS = -Wall -g3 -ggdb -I$(top_srcdir)/external/http_parser  -I$(jalsoninc)
AM_CXXFLAGS = -I$(LIBUVHOME)/include -Wall  -std=c++11

AM_LDFLAGS=-lpthread

# Primary defination of our shared library to be created.  Notice the
# _LTLIBRARIES key: automake is looking specifically for this pattern and then
# generating make rules which will invoke libtool.
#
# The "lib_" prefix indicates that the named products are to be installed in
# the $(libdir) directory. If we want to build a library that does not get
# installed, then we should use the prefix "noinst_".
lib_LTLIBRARIES = libXXX.la

# The "include_" prefix includes a list of headers to be installed.  The
# "nobase_" additional prefix means the directory names are copied too.
nobase_include_HEADERS = XXX/types.h XXX/kernel.h XXX/wamp_session.h			\
XXX/dealer_service.h  XXX/io_listener.h XXX/protocol.h \
XXX/rawsocket_protocol.h XXX/websocket_protocol.h								\
XXX/tcp_socket.h XXX/utils.h XXX/data_model.h

# List the sources for an individual library
libXXX_la_SOURCES = tcp_socket.cc dealer_service.cc event_loop.cc			\
 io_loop.cc kernel.cc pubsub_man.cc rpc_man.cc \
utils.cc wamp_session.cc protocol.cc rawsocket_protocol.cc					\
websocket_protocol.cc ../external/http_parser/http_parser.c http_parser.cc	\
data_model.cc


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
libXXX_la_LIBADD  =  -lpthread

# Note: version info for shared libraries is three number system, where the
# numbers represent: CURRENT : REVISION : AGE
#
# - CURRENT:  library version. Only change if API has changed.
# - REVISION: revision of current version. Incr. base on internal changes.
# - AGE: indicates compatibilty with previous version of the shlib.
#
#libexio_la_LDFLAGS =  -version-info 1:7:0 -L$(XLOGHOME)/lib -lxlog
libXXX_la_LDFLAGS =  -version-info 1:0:0

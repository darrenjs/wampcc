#
# Copyright (c) 2017 Darren Smith
#
# wampcc is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

# NOTE: AM_CPPFLAGS is ignored in preference to a per-executable (or
# per-library) _CPPFLAGS variable if it is defined
#
# NOTE: it is not good practice to add "-Wall" and "-03" etc here.  Those
# choices should be made by the user when they invoke the configure script.
AM_CPPFLAGS = -I$(jalsoninc) $(libuvinc) -I$(top_srcdir)/lib  -Wall -g3 -ggdb -std=c++11

AM_LDFLAGS=-L../lib -lwampcc $(LIBLS) -L$(jalsonlib) -lwampcc_json  $(libuvlib) -lcrypto -lpthread

noinst_PROGRAMS=basic_embedded_router basic_publisher basic_subscriber	\
basic_caller basic_callee router wampcc_tester ssl_client ssl_server	\
basic_callee_ssl

basic_embedded_router_SOURCES=basic/basic_embedded_router.cc
basic_publisher_SOURCES=basic/basic_publisher.cc
basic_subscriber_SOURCES=basic/basic_subscriber.cc
basic_caller_SOURCES=basic/basic_caller.cc
basic_callee_SOURCES=basic/basic_callee.cc
basic_callee_ssl_SOURCES=basic/basic_callee_ssl.cc
router_SOURCES=wamp_router/router.cc
wampcc_tester_SOURCES=tester/wampcc_tester.cc
ssl_client_SOURCES=ssl_socket/ssl_client.cc
ssl_server_SOURCES=ssl_socket/ssl_server.cc

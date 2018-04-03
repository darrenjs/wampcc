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
AM_CPPFLAGS = -I$(jalsoninc) $(libuvinc) -I$(top_srcdir)/libs/wampcc  -Wall -g3 -ggdb -std=c++11

AM_LDFLAGS=-L../libs/wampcc -lwampcc $(LIBLS) -L$(jalsonlib) -lwampcc_json  $(libuvlib) -lcrypto -lpthread

# for make dist
EXTRA_DIST=server.key server.crt README.md message_server examples.makefile	\
json/json_mass_encode_decode.cc CMakeLists.txt

noinst_PROGRAMS=basic_embedded_router basic_publisher basic_subscriber	\
basic_caller basic_callee router wampcc_tester ssl_client ssl_server	\
basic_callee_ssl basic_json basic_server basic_async_callee demo_client	\
demo_embedded_router demo_embedded_router_ssl

basic_server_SOURCES=basic/basic_server.cc
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
basic_json_SOURCES=json/basic_json.cc
basic_async_callee_SOURCES=basic/basic_async_callee.cc
demo_client_SOURCES=basic/demo_client.cc
demo_embedded_router_SOURCES=basic/demo_embedded_router.cc
demo_embedded_router_ssl_SOURCES=basic/demo_embedded_router_ssl.cc

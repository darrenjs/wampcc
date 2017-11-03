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
AM_CPPFLAGS =   -I$(jalsoninc) $(libuvinc) -I$(top_srcdir)/libs/wampcc  -Wall -g3 -ggdb -std=c++11 -O0

AM_LDFLAGS=-lpthread

# for make dist
EXTRA_DIST=CMakeLists.txt

bin_PROGRAMS = admin

admin_SOURCES=admin.cc
admin_LDADD=-L../libs/wampcc -lwampcc  $(LIBLS) -L$(jalsonlib) -lwampcc_json  $(libuvlib)  -lcrypto -lpthread
admin_LDFLAGS=-L../libs/wampcc -pthread

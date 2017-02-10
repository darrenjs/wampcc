## Makefile.am -- Process this file with automake to produce Makefile.in
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2, or (at your option)
## any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

# NOTE: AM_CPPFLAGS is ignored in preference to a per-executable (or
# per-library) _CPPFLAGS variable if it is defined
#
# NOTE: it is not good practice to add "-Wall" and "-03" etc here.  Those
# choices should be made by the user when they invoke the configure script.
AM_CPPFLAGS =   -I$(jalsoninc) $(libuvinc) -I$(top_srcdir)/lib  -Wall -g3 -ggdb -std=c++11 -O0

AM_LDFLAGS=-lpthread

bin_PROGRAMS = admin

admin_SOURCES=admin.cc
admin_LDADD=-L../lib -lXXX  $(LIBLS) -L$(jalsonlib) -ljalson  $(libuvlib)  -lcrypto -lpthread
admin_LDFLAGS=-L../lib -pthread


AM_CPPFLAGS =  -I$(top_srcdir)/lib -I$(LIBUVHOME)/include -I$(JALSONHOME)/include -Wall -g3 -ggdb -std=c++0x -O0

AM_LDFLAGS=-lpthread -L../lib -lXXX  $(LIBLS) -L$(JALSONHOME)/lib -ljalson -L$(LIBUVHOME)/lib -luv -lcrypto -lpthread


TESTS=test_connect_timeout

noinst_PROGRAMS=test_connect_timeout
#noinst_PROGRAMS=server_demo

test_connect_timeout_SOURCES=test_connect_timeout.cc

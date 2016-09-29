
# We are using GoogleTest, so here we define that 'make check' depends on
# libgtest, and provide the sources and compile & link for it to be built by
# autotools.
#
# http://stackoverflow.com/questions/35998856/how-can-i-use-google-test-with-my-project-that-builds-via-autotools

check_LTLIBRARIES    = libgtest.la
libgtest_la_SOURCES  = ../external/googletest/googletest/src/gtest-all.cc
libgtest_la_CPPFLAGS = -I$(top_srcdir)/external/googletest/googletest/include -I$(top_srcdir)/external/googletest/googletest
libgtest_la_LDFLAGS  = -pthread

# Define compile & link flags for each target
AM_CPPFLAGS = -I$(top_srcdir)/lib -I$(LIBUVHOME)/include						\
-I$(JALSONHOME)/include -I$(top_srcdir)/external/googletest/googletest/include			\
-I$(top_srcdir)/external/googletest/googletest -Wall -g3 -ggdb -std=c++0x -O0 -pthread

AM_LDFLAGS=-lpthread -L../lib -lXXX  $(LIBLS) -L$(JALSONHOME)/lib -ljalson -L$(LIBUVHOME)/lib -luv -lcrypto -lpthread

check_PROGRAMS=test_connect_timeout test_late_wamp_session_descructor
noinst_PROGRAMS=test_connect_timeout test_late_wamp_session_descructor
TESTS=test_connect_timeout test_late_wamp_session_descructor


test_connect_timeout_SOURCES=test_connect_timeout.cc
test_connect_timeout_LDADD=libgtest.la

test_late_wamp_session_descructor_SOURCES=test_late_wamp_session_descructor.cc
test_late_wamp_session_descructor_LDADD=libgtest.la

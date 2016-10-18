
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

check_PROGRAMS=test_connect_timeout test_late_wamp_session_destructor		\
test_early_wamp_session_destructor test_evthread_wamp_session_destructor	\
test_unused_wamp_connector test_dealer_disconnect_when_has_connections		\
test_late_dealer_destructor test_tcp_socket
noinst_PROGRAMS=$(check_PROGRAMS)
TESTS=$(check_PROGRAMS)

test_connect_timeout_SOURCES=test_connect_timeout.cc
test_connect_timeout_LDADD=libgtest.la

test_late_wamp_session_destructor_SOURCES=test_late_wamp_session_destructor.cc
test_late_wamp_session_destructor_LDADD=libgtest.la

test_early_wamp_session_destructor_SOURCES=test_early_wamp_session_destructor.cc
test_early_wamp_session_destructor_LDADD=libgtest.la

test_evthread_wamp_session_destructor_SOURCES=test_evthread_wamp_session_destructor.cc
test_evthread_wamp_session_destructor_LDADD=libgtest.la

test_unused_wamp_connector_SOURCES=test_unused_wamp_connector.cc
test_unused_wamp_connector_LDADD=libgtest.la

test_dealer_disconnect_when_has_connections_SOURCES=test_unused_wamp_connector.cc
test_dealer_disconnect_when_has_connections_LDADD=libgtest.la

test_late_dealer_destructor_SOURCES=test_late_dealer_destructor.cc
test_late_dealer_destructor_LDADD=libgtest.la

test_tcp_socket_SOURCES=test_tcp_socket.cc
test_tcp_socket_LDADD=libgtest.la

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
AM_CPPFLAGS = -I$(top_srcdir)/lib  $(libuvinc)						\
-I$(jalsoninc) -I$(top_srcdir)/external/googletest/googletest/include			\
-I$(top_srcdir)/external/googletest/googletest -Wall -g3 -ggdb -std=c++0x -O0 -pthread

AM_LDFLAGS=-lpthread -L../lib -lXXX  $(LIBLS)  -L$(jalsonlib) -ljalson  $(libuvlib) -lcrypto -lpthread


check_PROGRAMS=test_connect_timeout test_tcp_socket_connect					\
test_evthread_wamp_session_destructor test_early_wamp_session_destructor	\
test_late_wamp_session_destructor test_late_dealer_destructor				\
test_dealer_disconnect_when_has_connections 		\
test_tcp_socket_listen test_tcp_socket_passive_disconnect					\
test_wamp_session_fast_close

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

test_dealer_disconnect_when_has_connections_SOURCES=test_dealer_disconnect_when_has_connections.cc
test_dealer_disconnect_when_has_connections_LDADD=libgtest.la

test_late_dealer_destructor_SOURCES=test_late_dealer_destructor.cc
test_late_dealer_destructor_LDADD=libgtest.la

test_tcp_socket_connect_SOURCES=test_tcp_socket_connect.cc
test_tcp_socket_connect_LDADD=libgtest.la

test_tcp_socket_listen_SOURCES=test_tcp_socket_listen.cc
test_tcp_socket_listen_LDADD=libgtest.la

test_tcp_socket_passive_disconnect_SOURCES=test_tcp_socket_passive_disconnect.cc
test_tcp_socket_passive_disconnect_LDADD=libgtest.la

test_wamp_session_fast_close_SOURCES=test_wamp_session_fast_close.cc
test_wamp_session_fast_close_LDADD=libgtest.la

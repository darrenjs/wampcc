# NOTE: it is not good practice to add "-Wall" and "-03" etc here.  Those
# choices should be made by the user when they invoke the configure script.
AM_CPPFLAGS = -I$(top_srcdir)/json/src -Wall -pthread -Wall -std=c++11

# NOTE: -lrt added for posix clock support
AM_LDFLAGS=-L$(top_builddir)/json/src -lwampcc_json -lrt -pthread

noinst_PROGRAMS=hello memtest test_encode_decode
#noinst_PROGRAMS=server_demo


hello_SOURCES=hello.cc
hello_LDADD=$(janssonlib)

memtest_SOURCES=memtest.cc
memtest_LDADD=$(janssonlib)

test_encode_decode_SOURCES=test_encode_decode.cc
test_encode_decode_LDADD=$(janssonlib)

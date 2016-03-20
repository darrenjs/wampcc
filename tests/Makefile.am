


# NOTE: it is not good practice to add "-Wall" and "-03" etc here.  Those
# choices should be made by the user when they invoke the configure script.
AM_CPPFLAGS = -I$(top_srcdir)/libjalson -Wall -pthread -Wall

# NOTE: -lrt added for posix clock support
AM_LDFLAGS=-L$(top_builddir)/libjalson -ljalson -lrt -pthread

TESTS=test_json_pointer

noinst_PROGRAMS=test_json_pointer
#noinst_PROGRAMS=server_demo


test_json_pointer_SOURCES=test_json_pointer.cc
test_json_pointer_LDADD=$(janssonlib)

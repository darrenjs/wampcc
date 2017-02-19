# NOTE: it is not good practice to add "-Wall" and "-03" etc here.  Those
# choices should be made by the user when they invoke the configure script.
AM_CPPFLAGS = -I$(top_srcdir)/src -Wall -pthread -Wall -std=c++11 -DJALSONDIR=\"${top_srcdir}\"

# NOTE: -lrt added for posix clock support
AM_LDFLAGS=-L$(top_builddir)/src -lwampcc_json -lrt -pthread

TESTS=test_json_pointer test_json_patch test_json_patch2 test_basic_jalson test_single_functions

noinst_PROGRAMS=test_json_pointer test_json_patch test_json_patch2 test_basic_jalson test_single_functions
#noinst_PROGRAMS=server_demo


test_json_pointer_SOURCES=test_json_pointer.cc
test_json_pointer_LDADD=$(janssonlib)
test_json_patch_SOURCES=test_json_patch.cc
test_json_patch_LDADD=$(janssonlib)
test_json_patch2_SOURCES=test_json_patch2.cc
test_json_patch2_LDADD=$(janssonlib)

test_basic_jalson_SOURCES=test_basic_jalson.cc
test_basic_jalson_LDADD=$(janssonlib)

test_single_functions_SOURCES=test_single_functions.cc
test_single_functions_LDADD=$(janssonlib)

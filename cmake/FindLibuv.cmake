# Locate libuv library
# This module defines
#  LIBUV_FOUND, if false, do not try to link to libuv
#  LIBUV_LIBRARIES
#  LIBUV_INCLUDE_DIRS, where to find uv.h

FIND_PATH(LIBUV_INCLUDE_DIRS NAMES uv.h HINTS ${LIBUV_DIR}/include)
FIND_LIBRARY(LIBUV_LIBRARIES NAMES uv libuv HINTS ${LIBUV_DIR}/Debug/lib ${LIBUV_DIR}/lib)

if(WIN32)
  list(APPEND LIBUV_LIBRARIES iphlpapi)
  list(APPEND LIBUV_LIBRARIES psapi)
  list(APPEND LIBUV_LIBRARIES userenv)
  list(APPEND LIBUV_LIBRARIES ws2_32)
endif()

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBUV DEFAULT_MSG LIBUV_LIBRARIES LIBUV_INCLUDE_DIRS)

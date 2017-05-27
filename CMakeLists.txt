##+----------------------------------------------------------------------------+
##| jalson (library)
##+----------------------------------------------------------------------------+

# Example of invocation on Linux
#
#  $ cmake -DJANSSON_INC_DIR=/opt/jansson-2.7/include -DJANSSON_LIB_DIR=/opt/jansson-2.7/lib  -DCMAKE_INSTALL_PREFIX=/opt/jalson -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON ../src
#
#

cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

set(PROJECT_NAME jalson)

# configure for C++ project
project(${PROJECT_NAME} CXX)

##
## Check that user has provided location to jansson
##
if (NOT DEFINED JANSSON_INC_DIR)
  message(FATAL_ERROR "Please define: JANSSON_INC_DIR")
endif()

if (NOT DEFINED JANSSON_LIB_DIR)
  message(FATAL_ERROR "Please define: JANSSON_LIB_DIR")
endif()

# normalise user paths that we use for searching
file(TO_CMAKE_PATH ${JANSSON_INC_DIR} JANSSON_INC_DIR)
file(TO_CMAKE_PATH ${JANSSON_LIB_DIR} JANSSON_LIB_DIR)

##
## Platform checks, and generate config.h
##
include(CheckLibraryExists)
check_library_exists(jansson json_dumps "${JANSSON_LIB_DIR}" HAVE_JANSSON)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

## Paths

message(STATUS "Building ${PROJECT_NAME} on: ${CMAKE_SYSTEM_NAME}")

set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH
    "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH
    "Installation directory for headers")

if(CMAKE_HOST_UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

include_directories(
  ${PROJECT_SOURCE_DIR}/src
  ${PROJECT_SOURCE_DIR}/external/msgpack-c/include
  ${CMAKE_CURRENT_BINARY_DIR}
  ${INSTALL_INC_DIR} )

##
## wampcc-json library
##

# Link to jansson shared library
set ( PROJECT_LINK_LIBS libjansson )
link_directories( ${JANSSON_LIB_DIR} )
include_directories( ${JANSSON_INC_DIR} )

# Source files
file(GLOB LIB_SRC_FILES ${PROJECT_SOURCE_DIR}/src/*.cc)
file(GLOB HDR_FILES ${PROJECT_SOURCE_DIR}/src/wampcc/*.h)

add_library(wampcc_json_static STATIC  ${LIB_SRC_FILES})
set_target_properties(wampcc_json_static PROPERTIES OUTPUT_NAME wampcc_json)
list(APPEND TO_INSTALL wampcc_json_static)

if(CMAKE_HOST_UNIX)
  add_library(wampcc_json_shared SHARED  ${LIB_SRC_FILES})
  set_target_properties(wampcc_json_shared PROPERTIES OUTPUT_NAME wampcc_json)
  list(APPEND TO_INSTALL wampcc_json_shared)
endif()

##
## install
##

install(TARGETS ${TO_INSTALL}
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}")
install(FILES ${HDR_FILES}
    DESTINATION "${INSTALL_INC_DIR}/wampcc")

#end

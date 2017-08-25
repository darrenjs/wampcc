##+----------------------------------------------------------------------------+
##| wampcc
##+----------------------------------------------------------------------------+

cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

set(PROJECT_NAME wampcc)
project(${PROJECT_NAME} CXX C)
#project(${PROJECT_NAME} VERSION 1.4 LANGUAGES CXX C)


##
## Check that user has provided location to libuv
##
if (NOT DEFINED LIBUV_DIR)
  message(FATAL_ERROR "Please define: LIBUV_DIR")
endif()

##
## Check that user has provided location to jansson
##
if (NOT DEFINED JANSSON_DIR)
  message(FATAL_ERROR "Please define: JANSSON_DIR")
endif()


# normalise user paths that we use for searching
file(TO_CMAKE_PATH ${LIBUV_DIR} LIBUV_DIR)
file(TO_CMAKE_PATH ${JANSSON_DIR} JANSSON_DIR)

message(STATUS "Building ${PROJECT_NAME} on: ${CMAKE_SYSTEM_NAME}")

set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH
    "Installation directory for executables")
set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH
    "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH
    "Installation directory for headers")

include_directories(${PROJECT_SOURCE_DIR}/lib)
include_directories(${PROJECT_SOURCE_DIR}/json/src)
include_directories(${PROJECT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LIBUV_DIR}/include)

include_directories(${PROJECT_SOURCE_DIR}/3rdparty/websocketpp)
include_directories(${PROJECT_SOURCE_DIR}/3rdparty)

##
## Platform checks, and generate config.h
##
include(CheckIncludeFiles)
check_include_files(dlfcn.h HAVE_DLFCN_H)
check_include_files(getopt.h HAVE_GETOPT_H)
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(stdbool.h HAVE_STDBOOL_H)
check_include_files(memory.h HAVE_MEMORY_H)
check_include_files(stdint.h HAVE_STDINT_H)
check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(strings.h HAVE_STRINGS_H)
check_include_files(sys/stat.h HAVE_SYS_STAT_H)
check_include_files(sys/types.h HAVE_SYS_TYPES_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files("stdlib.h;stdarg.h;string.h;float.h" STDC_HEADERS)

## Check for libuv. Handle its name variation on different platforms.

if(CMAKE_HOST_UNIX)
    set(LIBUV_FILE "uv")
else()
    set(LIBUV_FILE "libuv")
endif()

message(STATUS "looking for libuv under ${LIBUV_DIR}/lib")
include(CheckLibraryExists)

check_library_exists(${LIBUV_FILE} uv_version ${LIBUV_DIR}/lib HAVE_LIBUV)

if(NOT HAVE_LIBUV)
  message(FATAL_ERROR "libuv not found")
endif()

# check websocketpp is available in the source tree
set(websocketpp "${PROJECT_SOURCE_DIR}/3rdparty/websocketpp/websocketpp/message_buffer/message.hpp")
message(STATUS "checking for ${websocketpp}")
if(NOT EXISTS "${websocketpp}")
  message(FATAL_ERROR "websocketpp header not found! Check websocketpp unzipped under 3rdparty/")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

if(CMAKE_HOST_UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

set(LIB_EXTNL_SLRE_SRC_FILES)
file(GLOB HDR_FILES ${PROJECT_SOURCE_DIR}/lib/wampcc/*.h)
file(GLOB LIB_MAIN_SRC_FILES ${PROJECT_SOURCE_DIR}/lib/*.cc)
file(GLOB LIB_EXTNL_HTTPPARSER_SRC_FILES ${PROJECT_SOURCE_DIR}/3rdparty/http_parser/*.c)
file(GLOB LIB_EXTNL_APACH_SRC_FILES ${PROJECT_SOURCE_DIR}/3rdparty/apache/*.c)
file(GLOB EXE_SRC_FILES ${PROJECT_SOURCE_DIR}/src/*.cc)

# list of wampcc & wampcc_json headers file to install
set(INSTALL_HDRS
  ${PROJECT_SOURCE_DIR}/json/src/wampcc/json.h
  ${PROJECT_SOURCE_DIR}/json/src/wampcc/json_internals.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/version.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/types.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/kernel.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/wamp_session.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/wamp_router.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/protocol.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/rawsocket_protocol.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/websocket_protocol.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/tcp_socket.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/data_model.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/error.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/wampcc.h
  ${PROJECT_SOURCE_DIR}/lib/wampcc/ssl_socket.h)

# TODO: probably don't need INSTALL_LIB_DIR in list of link dirs.
link_directories(${INSTALL_LIB_DIR} ${LIBUV_DIR}/lib ${JANSSON_DIR}/lib)

##
## wampcc-json library
##

# check msgpack is available in the source tree
set(msgpackfile "${PROJECT_SOURCE_DIR}/3rdparty/msgpack-c/include/msgpack.h")
message(STATUS "checking for ${msgpackfile}")
if(NOT EXISTS "${msgpackfile}")
  message(FATAL_ERROR "msgpack header not found! Check msgpack unzipped under 3rdparty/")
endif()

# source files
file(GLOB WAMPCC_JSON_SRC_FILES ${PROJECT_SOURCE_DIR}/json/src/*.cc)

add_library(wampcc_json_static STATIC ${WAMPCC_JSON_SRC_FILES})
set_target_properties(wampcc_json_static PROPERTIES OUTPUT_NAME wampcc_json)
target_include_directories(wampcc_json_static
                           PRIVATE ${PROJECT_SOURCE_DIR}/3rdparty/msgpack-c/include
                           ${JANSSON_DIR}/include )

list(APPEND TO_INSTALL wampcc_json_static)

if(CMAKE_HOST_UNIX)
  add_library(wampcc_json_shared SHARED ${WAMPCC_JSON_SRC_FILES})
  set_target_properties(wampcc_json_shared PROPERTIES OUTPUT_NAME wampcc_json)
  target_include_directories(wampcc_json_shared
                             PRIVATE ${PROJECT_SOURCE_DIR}/3rdparty/msgpack-c/include
                             ${JANSSON_DIR}/include )
  list(APPEND TO_INSTALL wampcc_json_shared)
endif()

##
## wampcc library
##

add_library(wampcc STATIC
    ${HDR_FILES}
    ${LIB_MAIN_SRC_FILES}
    ${LIB_EXTNL_HTTPPARSER_SRC_FILES}
    ${LIB_EXTNL_APACH_SRC_FILES})

target_link_libraries(wampcc wampcc_json_static)
add_dependencies(wampcc wampcc_json_static)
list(APPEND TO_INSTALL wampcc)

##
## test & example programs
##

set(COMMON_LIBS wampcc wampcc_json_static)
set(COMMON_DEPS wampcc wampcc_json_static)

if (WIN32)
  list(APPEND COMMON_LIBS libuv ssleay32 libeay32)
  # libuv library dependencies
  list(APPEND COMMON_LIBS advapi32 iphlpapi psapi shell32 user32 userenv ws2_32)
else()
  list(APPEND COMMON_LIBS uv crypto ssl pthread)
endif()

list(APPEND COMMON_LIBS jansson)

# executable
add_executable(test_misc
  ${PROJECT_SOURCE_DIR}/test/test_misc.cc
  ${PROJECT_SOURCE_DIR}/test/test_common.h )
add_dependencies(test_misc ${COMMON_DEPS})
target_link_libraries(test_misc ${COMMON_LIBS})

if (WIN32)
  set_target_properties(test_misc PROPERTIES LINK_FLAGS "/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib")
endif()


# executable
add_executable(example_basic_embedded_router
  ${PROJECT_SOURCE_DIR}/examples/basic/basic_embedded_router.cc )
add_dependencies(example_basic_embedded_router ${COMMON_DEPS})
target_link_libraries(example_basic_embedded_router ${COMMON_LIBS})

if (WIN32)
  set_target_properties(example_basic_embedded_router PROPERTIES LINK_FLAGS "/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib")
endif()

##
## utility programs
##

if (NOT WIN32)
  add_executable(admin ${EXE_SRC_FILES})
  add_dependencies(admin ${COMMON_DEPS})
  target_link_libraries(admin ${COMMON_LIBS})
  list(APPEND TO_INSTALL admin)
endif()

##
## install
##

install(TARGETS ${TO_INSTALL}
    RUNTIME DESTINATION "${INSTALL_BIN_DIR}"
    BUNDLE  DESTINATION "${INSTALL_BIN_DIR}"
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}")
install(FILES ${INSTALL_HDRS}
    DESTINATION "${INSTALL_INC_DIR}/wampcc")

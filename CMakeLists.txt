##+----------------------------------------------------------------------------+
##| wampcc
##+----------------------------------------------------------------------------+

cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

set(PROJECT_NAME wampcc)
project(${PROJECT_NAME} CXX C)
#project(${PROJECT_NAME} VERSION 1.3.1 LANGUAGES CXX C)

message(STATUS "Building ${PROJECT_NAME} on: ${CMAKE_SYSTEM_NAME}")

set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH
    "Installation directory for executables")
set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH
    "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH
    "Installation directory for headers")

include_directories(${PROJECT_SOURCE_DIR}/lib)
include_directories(${PROJECT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${INSTALL_INC_DIR})

include_directories(${PROJECT_SOURCE_DIR}/external/websocketpp)
include_directories(${PROJECT_SOURCE_DIR}/external)

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

include(CheckLibraryExists)
check_library_exists(libuv uv_version ${INSTALL_LIB_DIR} HAVE_LIBUV)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

if(CMAKE_HOST_UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

set(LIB_EXTNL_SLRE_SRC_FILES)
file(GLOB HDR_FILES ${PROJECT_SOURCE_DIR}/lib/wampcc/*.h)
file(GLOB LIB_MAIN_SRC_FILES ${PROJECT_SOURCE_DIR}/lib/*.cc)
file(GLOB LIB_EXTNL_HTTPPARSER_SRC_FILES ${PROJECT_SOURCE_DIR}/external/http_parser/*.c)
file(GLOB LIB_EXTNL_APACH_SRC_FILES ${PROJECT_SOURCE_DIR}/external/apache/*.c)
file(GLOB EXE_SRC_FILES ${PROJECT_SOURCE_DIR}/src/*.cc)

# list of wampcc headers file to install
set(INSTALL_HDRS
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

link_directories(${INSTALL_LIB_DIR})

set(COMMON_LIBS wampcc wampcc_json jansson)

if (WIN32)
  list(APPEND COMMON_LIBS libuv ssleay32 libeay32)
  # libuv library dependencies
  list(APPEND COMMON_LIBS advapi32 iphlpapi psapi shell32 user32 userenv ws2_32)
else()
  list(APPEND COMMON_LIBS uv crypto ssl)
endif()

##
## wampcc library
##

add_library(wampcc STATIC
    ${HDR_FILES}
    ${LIB_MAIN_SRC_FILES}
    ${LIB_EXTNL_HTTPPARSER_SRC_FILES}
    ${LIB_EXTNL_APACH_SRC_FILES})

list(APPEND TO_INSTALL wampcc)

##
## test programs
##

add_executable(test_misc
  ${PROJECT_SOURCE_DIR}/test/test_misc.cc
  ${PROJECT_SOURCE_DIR}/test/test_common.h )
target_link_libraries(test_misc ${COMMON_LIBS})

if (WIN32)
  set_target_properties(test_misc PROPERTIES LINK_FLAGS "/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib")
endif()

##
## wampcc-json library (work in progress)
##

# # how to make this include specific only from wampcc-json ?
# include_directories(${PROJECT_SOURCE_DIR}/external/msgpack-c/include)

# file(GLOB LIBJSON_SRC_FILES ${PROJECT_SOURCE_DIR}/jalson/src/*.cc ${PROJECT_SOURCE_DIR}/jalson/src/*.h)
# file(GLOB LIBJSON_HDR_FILES ${PROJECT_SOURCE_DIR}/jalson/src/wampcc/*.h)

# add_library(wampcc_json STATIC ${LIBJSON_SRC_FILES})

# #set_target_properties(wampcc_json_static PROPERTIES OUTPUT_NAME wampcc_json)
# list(APPEND TO_INSTALL wampcc_json)

# if (NOT WIN32)
#   add_library(wampcc_json_shared SHARED  ${LIB_SRC_FILES})
#   set_target_properties(wampcc_json_shared PROPERTIES OUTPUT_NAME wampcc_json)
#   list(APPEND TO_INSTALL wampcc_json_shared)
# endif()

##
## example programs
##

add_executable(example_basic_embedded_router
  ${PROJECT_SOURCE_DIR}/examples/basic/basic_embedded_router.cc )
target_link_libraries(example_basic_embedded_router ${COMMON_LIBS})

if (WIN32)
  set_target_properties(example_basic_embedded_router PROPERTIES LINK_FLAGS "/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib")
endif()

##
## utility programs
##

if (NOT WIN32)
  add_executable(wampccadmin ${EXE_SRC_FILES})
  target_link_libraries(wampccadmin ${COMMON_LIBS})
  list(APPEND TO_INSTALL wampccadmin)
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

##+--------------------------------------------------------------------------------------------+
##| wampcc
##+--------------------------------------------------------------------------------------------+

cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

set(PROJECT_NAME wampcc)
project(${PROJECT_NAME} CXX C)

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
check_library_exists(uv uv_version ${INSTALL_LIB_DIR} HAVE_LIBUV)

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

add_library(wampcc STATIC
    ${LIB_MAIN_SRC_FILES}
    ${LIB_EXTNL_HTTPPARSER_SRC_FILES}
    ${LIB_EXTNL_APACH_SRC_FILES})

link_directories(${INSTALL_LIB_DIR})

set(COMMON_LIBS wampcc wampcc_json jansson)

if (WIN32)
  list(APPEND COMMON_LIBS libuv)
  list(APPEND COMMON_LIBS advapi32 iphlpapi psapi shell32 user32 userenv ws2_32)
endif()

add_executable(test_misc
  ${PROJECT_SOURCE_DIR}/test/test_misc.cc
  ${PROJECT_SOURCE_DIR}/test/test_common.h )
target_link_libraries(test_misc ${COMMON_LIBS})

add_executable(wampccadmin ${EXE_SRC_FILES})
target_link_libraries(wampccadmin ${COMMON_LIBS})

list(APPEND TO_INSTALL wampcc wampccadmin)

install(TARGETS ${TO_INSTALL}
    RUNTIME DESTINATION "${INSTALL_BIN_DIR}"
    BUNDLE  DESTINATION "${INSTALL_BIN_DIR}"
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}")
install(FILES ${HDR_FILES}
    DESTINATION "${INSTALL_INC_DIR}/wampcc")

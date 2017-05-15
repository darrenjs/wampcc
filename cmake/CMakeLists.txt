##+--------------------------------------------------------------------------------------------+
##| jalson (library)
##+--------------------------------------------------------------------------------------------+

cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

set(PROJECT_NAME jalson)

# Path to jansson library
set(JANSSON_PATH_LIB /home/darrens/opt/jansson-2.7/lib)
set(JANSSON_PATH_INC /home/darrens/opt/jansson-2.7/include)

project(${PROJECT_NAME} CXX)

message(STATUS "Building ${PROJECT_NAME} on: ${CMAKE_SYSTEM_NAME}")

set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH
    "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH
    "Installation directory for headers")

if(CMAKE_HOST_UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

include_directories(${PROJECT_SOURCE_DIR}/../src ${PROJECT_SOURCE_DIR}/../external/msgpack-c/include ${PROJECT_SOURCE_DIR}/../cmake)
include_directories(${INSTALL_INC_DIR})

# Link to jansson shared library:
set ( PROJECT_LINK_LIBS libjansson )
link_directories( ${JANSSON_PATH_LIB} )
include_directories( ${JANSSON_PATH_INC} )

# Source files
file(GLOB LIB_SRC_FILES ${PROJECT_SOURCE_DIR}/../src/*.cc)
file(GLOB HDR_FILES ${PROJECT_SOURCE_DIR}/../src/wampcc/*.h)

# Installation
add_library(wampcc_json_static STATIC  ${LIB_SRC_FILES})
add_library(wampcc_json_shared SHARED  ${LIB_SRC_FILES})

set_target_properties(wampcc_json_static PROPERTIES OUTPUT_NAME wampcc_json)
set_target_properties(wampcc_json_shared PROPERTIES OUTPUT_NAME wampcc_json)
list(APPEND TO_INSTALL wampcc_json_static wampcc_json_shared)

install(TARGETS ${TO_INSTALL}
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}")
install(FILES ${HDR_FILES}
    DESTINATION "${INSTALL_INC_DIR}/wampcc")

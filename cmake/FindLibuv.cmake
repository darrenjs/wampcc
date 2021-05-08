#[=======================================================================[.rst:
FindLibUV
---------

Find libuv includes and library.

Imported Targets
^^^^^^^^^^^^^^^^

An :ref:`imported target <Imported targets>` named
``LibUV::LibUV`` is provided if libuv has been found.

Result Variables
^^^^^^^^^^^^^^^^

This module defines the following variables:

``LibUV_FOUND``
  True if libuv was found, false otherwise.
``LibUV_INCLUDE_DIRS``
  Include directories needed to include libuv headers.
``LibUV_LIBRARIES``
  Libraries needed to link to libuv.
``LibUV_VERSION``
  The version of libuv found.
``LibUV_VERSION_MAJOR``
  The major version of libuv.
``LibUV_VERSION_MINOR``
  The minor version of libuv.
``LibUV_VERSION_PATCH``
  The patch version of libuv.

Cache Variables
^^^^^^^^^^^^^^^

This module uses the following cache variables:

``LibUV_LIBRARY``
  The location of the libuv library file.
``LibUV_INCLUDE_DIR``
  The location of the libuv include directory containing ``uv.h``.

The cache variables should not be used by project code.
They may be set by end users to point at libuv components.
#]=======================================================================]

#=============================================================================
# Copyright 2014-2016 Kitware, Inc.
# Modifed by S. Ghannadzadeh 2021

# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.

# Modified by S. Ghannadzadeh to:
# - prefer static version of libuv if USE_STATIC_LIBS is set
# - use LIBUV_DIR as well as LibUV_DIR for hints

if (USE_STATIC_LIBS)
  find_library(LibUV_LIBRARY NAMES uv_a uv libuv HINTS ${LibUV_DIR} ${LibUV_DIR}/lib ${LIBUV_DIR} ${LIBUV_DIR}/lib)
else()
  find_library(LibUV_LIBRARY NAMES uv uv_a libuv HINTS ${LibUV_DIR} ${LibUV_DIR}/lib ${LIBUV_DIR} ${LIBUV_DIR}/lib)
endif()
mark_as_advanced(LibUV_LIBRARY)

find_path(LibUV_INCLUDE_DIR NAMES uv.h HINTS ${LibUV_DIR}/include ${LIBUV_DIR}/include)
mark_as_advanced(LibUV_INCLUDE_DIR)

if(WIN32)
  set(LibUV_LIBRARIES_WIN
    psapi
    user32
    advapi32
    iphlpapi
    userenv
    ws2_32)
endif()

#-----------------------------------------------------------------------------
# Extract version number if possible.
set(_LibUV_H_REGEX "#[ \t]*define[ \t]+UV_VERSION_(MAJOR|MINOR|PATCH)[ \t]+[0-9]+")
if(LibUV_INCLUDE_DIR AND EXISTS "${LibUV_INCLUDE_DIR}/uv-version.h")
  file(STRINGS "${LibUV_INCLUDE_DIR}/uv/version.h" _LibUV_H REGEX "${_LibUV_H_REGEX}")
elseif(LibUV_INCLUDE_DIR AND EXISTS "${LibUV_INCLUDE_DIR}/uv.h")
  file(STRINGS "${LibUV_INCLUDE_DIR}/uv.h" _LibUV_H REGEX "${_LibUV_H_REGEX}")
else()
  set(_LibUV_H "")
endif()
foreach(c MAJOR MINOR PATCH)
  if(_LibUV_H MATCHES "#[ \t]*define[ \t]+UV_VERSION_${c}[ \t]+([0-9]+)")
    set(_LibUV_VERSION_${c} "${CMAKE_MATCH_1}")
  else()
    unset(_LibUV_VERSION_${c})
  endif()
endforeach()
if(DEFINED _LibUV_VERSION_MAJOR AND DEFINED _LibUV_VERSION_MINOR)
  set(LibUV_VERSION_MAJOR "${_LibUV_VERSION_MAJOR}")
  set(LibUV_VERSION_MINOR "${_LibUV_VERSION_MINOR}")
  set(LibUV_VERSION "${LibUV_VERSION_MAJOR}.${LibUV_VERSION_MINOR}")
  if(DEFINED _LibUV_VERSION_PATCH)
    set(LibUV_VERSION_PATCH "${_LibUV_VERSION_PATCH}")
    set(LibUV_VERSION "${LibUV_VERSION}.${LibUV_VERSION_PATCH}")
  else()
    unset(LibUV_VERSION_PATCH)
  endif()
else()
  set(LibUV_VERSION_MAJOR "")
  set(LibUV_VERSION_MINOR "")
  set(LibUV_VERSION_PATCH "")
  set(LibUV_VERSION "")
endif()
unset(_LibUV_VERSION_MAJOR)
unset(_LibUV_VERSION_MINOR)
unset(_LibUV_VERSION_PATCH)
unset(_LibUV_H_REGEX)
unset(_LibUV_H)

#-----------------------------------------------------------------------------
include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(LibUV
  REQUIRED_VARS LibUV_LIBRARY LibUV_INCLUDE_DIR
  VERSION_VAR LibUV_VERSION
    FAIL_MESSAGE
    "Could NOT find LibUV, try to set the path to LibUV root folder in LibUV_DIR")
set(LIBUV_FOUND ${LibUV_FOUND})

#-----------------------------------------------------------------------------
# Provide documented result variables and targets.
if(LibUV_FOUND)
  set(LibUV_INCLUDE_DIRS ${LibUV_INCLUDE_DIR})
  set(LibUV_LIBRARIES ${LibUV_LIBRARY})
  if(NOT TARGET LibUV::LibUV)
    add_library(LibUV::LibUV UNKNOWN IMPORTED)
    set_target_properties(LibUV::LibUV PROPERTIES
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${LibUV_LIBRARIES}"
      INTERFACE_INCLUDE_DIRECTORIES "${LibUV_INCLUDE_DIRS}"
      INTERFACE_LINK_LIBRARIES "${LibUV_LIBRARIES_WIN}")
  endif()
endif()

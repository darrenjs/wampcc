
#========== Initialisation ==========

# use 1.9, older, to work on SUSE 10
AC_INIT([jalson], [1.9], [jalson@darrenjs.net], [jalson], [ ] )
AC_PREREQ([2.59])

# This macro causes the environment variables, $host, $build and $target to be
# defined.
AC_CANONICAL_SYSTEM

# Not: the -Wall here is for automake errors; is unrelated to gcc errors
AM_INIT_AUTOMAKE([1.10 no-define -Wall])

# AM_PROG_AR is not available in automake v0.11 but it's essential in v0.12.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_CONFIG_HEADERS([config.h])
AC_PROG_CXX
AC_CONFIG_MACRO_DIR([m4])


# initialise libtool support

#LT_PREREQ([2.4.2]) # not 'technically' required, but good practice.


#========== Checks for programs ==========

AC_PROG_CXX
AC_PROG_CC
AM_PROG_LIBTOOL
AC_PROG_INSTALL


#========== Check for third party libraries ==========

have_vendor=0

# Specify a location for Jansson
AC_ARG_WITH(jansson, [ --with-jansson=PATH specify directory for the installed JANSSON library])

have_jansson=0
if test "x$with_jansson" != x; then
   janssonlib="$with_jansson/lib/libjansson.la"
   janssoninc="-I$with_jansson/include"
   have_jansson=1
   have_vendor=1
fi

# put the inc and lib into the makefiles
AC_SUBST(janssonlib)
AC_SUBST(janssoninc)

# put variable into config.h
AC_DEFINE_UNQUOTED([HAVE_JANSSON], [$have_jansson], [Define to 1 if Jannson library is present])


if test "x$have_vendor" = "x0" ; then
    AC_MSG_ERROR([You have not configured a JSON implementation. Try --help. Supported vendors: jansson])
fi


#========== Checks for header files ==========

AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h fcntl.h stdint.h stdio.h stdlib.h string.h time.h unistd.h sys/time.h sys/stat.h sys/syscall.h sys/mman.h sys/stat.h sys/types.h ])

AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE

AC_CHECK_FILE("${srcdir}/external/msgpack-c/include/msgpack.hpp",[ AC_MSG_NOTICE([msgpack found]) ],[
  AC_MSG_ERROR([Could not locate msgpack. Please ensure msgpack is downloaded into the external/ directory.])
])

#========== User options ==========

export DIRS="src examples/manual_tests tests"
extrabuild=

#========== Generation ==========

AC_SUBST(DIRS)


# List the files that will be generated. These are mainly makefiles, which
# automake will generate from the corresponding Makefile.am
AC_CONFIG_FILES([
Makefile
src/Makefile
examples/manual_tests/Makefile
tests/Makefile
])

# Trigger the generation of our makefiles
AC_OUTPUT

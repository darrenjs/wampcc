
#========== Initialisation ==========

AC_INIT([XXX], [1.0.0], [XXX-bug-report@darrenjs.net], [XXX], [ ] )
AC_PREREQ([2.59])

AC_CONFIG_AUX_DIR([.])

# This macro causes the environment variables, $host, $build and $target to be
# defined.
AC_CANONICAL_SYSTEM

# Note: the -Wall here is for automake errors; is unrelated to gcc errors
AM_INIT_AUTOMAKE([1.10 no-define -Wall foreign subdir-objects] )

AC_CONFIG_HEADERS([config.h])

AC_PROG_CXX
AC_LANG([C++])

AC_CONFIG_MACRO_DIR([m4])

# AM_PROG_AR not defined on redhat6
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# initialise libtool support
LT_INIT

#========== Checks for programs ==========

AC_PROG_CXX
AC_PROG_CC
AM_PROG_LIBTOOL
AC_PROG_INSTALL

m4_ifdef([AX_CXX_COMPILE_STDCXX_11], [
    AX_CXX_COMPILE_STDCXX_11
])


#========== Check for third party libraries ==========

#PKG_CHECK_MODULES([DEPS], [gtkmm-2.4 >= 2.12.2 somethingelse-1.0 >= 1.0.2])

#========== Checks for header files ==========

AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h strings.h unistd.h getopt.h])


AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE

##
## jalson - can either be included with the source code, or pulled in externally
## (although latter not yet implemented)
##

AC_MSG_NOTICE([Using bundled jalson])
internal_jalson=1
jalsoninc="../$srcdir/jalson/libjalson"
jalsonlib="../jalson/libjalson"
AC_SUBST(jalsoninc)
AC_SUBST(jalsonlib)

##########################################################################
# optional support for the admin static target
##########################################################################

dnl Example of default-enabled feature
AC_MSG_CHECKING([whether to build admin_static target])
AC_ARG_ENABLE([adminstatic],
    AS_HELP_STRING([--enable-adminstatic], [Enable admin_static static target (def=no)]),
    [enable_adminstatic="$enableval"],
    [enable_adminstatic=no],)
AC_MSG_RESULT([$enable_adminstatic])
AM_CONDITIONAL([USE_ADMINSTATIC], [test x"$enable_adminstatic" = x"yes" ])

##########################################################################



#========== Generation ==========

# List the files that will be generated. These are mainly makefiles, which
# automake will generate from the corresponding Makefile.am
AC_CONFIG_FILES([
Makefile
src/Makefile
lib/Makefile
test/Makefile
])

AC_CONFIG_SUBDIRS([jalson])

# Trigger the generation of our makefiles
AC_OUTPUT

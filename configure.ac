
#========== Initialisation ==========

AC_INIT([wampcc], [1.5], [wampcc@darrenjs.net], [wampcc], [ ] )
AC_PREREQ([2.59])

AC_CONFIG_AUX_DIR([.])

# This macro causes the environment variables, $host, $build and $target to be
# defined.
AC_CANONICAL_SYSTEM

# Note: the -Wall here is for automake errors; is unrelated to gcc errors
# Note: need tar-ustar to avoid using old tar format that has limit
#       on file path length of 99 chars
AM_INIT_AUTOMAKE([1.10 no-define -Wall foreign subdir-objects tar-ustar] )

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

# libuv is required by the project for network IO. Thus the user must provide
# the installed location during configuration.

have_libuv=0

AC_ARG_WITH(libuv, [  --with-libuv=PATH specify directory containing installation of libuv])

if test "x$with_libuv" != x; then
   libuvlib="-L$with_libuv/lib -luv"
   libuvinc="-I$with_libuv/include"
   have_libuv=1
else
   AC_CHECK_HEADER(uv.h, [have_libuv=1; libuvlib=-luv],
	AC_MSG_ERROR([You have not configured location of libuv. Try --help.]))
fi

# put the inc and lib into the makefiles
AC_SUBST(libuvlib)
AC_SUBST(libuvinc)

# put variable into config.h
AC_DEFINE_UNQUOTED([HAVE_LIBUV], [$have_libuv], [Define to 1 if libuv library is present])


#========== Checks for header files ==========

AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h strings.h unistd.h getopt.h])

AC_CHECK_HEADER(openssl/ssl.h, [openssl_ssl=1], [openssl_ssl=0])
if test "x$openssl_ssl" = "x0" ; then
    AC_MSG_ERROR([system header not found: openssl/ssl.h - please check the openssl dev package in installed on your system ])
fi

AC_CHECK_HEADER(openssl/hmac.h, [openssl_hmac=1], [openssl_hmac=0])
if test "x$openssl_hmac" = "x0" ; then
    AC_MSG_ERROR([system header not found: openssl/hmac.h - please check the openssl dev package in installed on your system ])
fi

AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE

# The user provided 'srcdir' might be a relative or an absolute path, depending
# on how the configure script was invoked. Here we obtain the absolute path to
# the srcdir.
wampcc_src_dir=`(cd "$srcdir"; pwd)`
build_dir=`(pwd)`

# log some directories known to configure
AC_MSG_NOTICE([notice build_dir: ${build_dir}])
AC_MSG_NOTICE([notice srcdir: ${srcdir}])
AC_MSG_NOTICE([notice prefix: ${prefix}])
AC_MSG_NOTICE([notice ac_pwd: ${ac_pwd}])
AC_MSG_NOTICE([notice wampcc_src_dir: ${wampcc_src_dir}])
AC_MSG_NOTICE([notice includedir: ${includedir}])


#========== json library, for wampcc_json ==========

# wampcc_json is wrapper around jansson, so detect if we have been told where to
# find jansson.
#

have_vendor=0

# Specify a location for Jansson
AC_ARG_WITH(jansson, [ --with-jansson=PATH specify directory for the installed JANSSON library])

have_jansson=0
if test "x$with_jansson" != x; then
   janssonlib="$with_jansson/lib/libjansson.la"
   janssoninc="-I$with_jansson/include"
   have_jansson=1
else
   AC_CHECK_HEADER(jansson.h, [ have_jansson=1; janssonlib=-ljansson ],
	AC_MSG_ERROR([You have not configured a JSON implementation. Try --help. Supported vendors: jansson]))
fi

# put the inc and lib into the makefiles
AC_SUBST(janssonlib)
AC_SUBST(janssoninc)

# put variable into config.h
AC_DEFINE_UNQUOTED([HAVE_JANSSON], [$have_jansson], [Define to 1 if Jannson library is present])


## Tell libwampcc where to find wampcc_json. Normally wampcc_json is under the
## json/ dir, but historically it was possible to pull it in from another
## location

AC_MSG_NOTICE([Using bundled jalson])
internal_jalson=1
jalsoninc="$(cd "$srcdir"; pwd)/include"
jalsonlib="${build_dir}/libs/json"
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
utils/Makefile
libs/Makefile
libs/wampcc/Makefile
libs/json/Makefile
tests/Makefile
tests/json/Makefile
tests/wampcc/Makefile
examples/Makefile
include/Makefile
])

# Trigger the generation of our makefiles
AC_OUTPUT

# The ACLOCAL_AMFLAGS variable is a requirement of using a macro
# sub-directory. According to the Automake documentation, this variable should
# be defined in the top-level Makefile.am file of any project that uses
# AC_CONFIG_MACRO_DIR in its configure.ac file. These flags indicate to
# aclocal where it should look for macro files when it's executed by rules
# defined in Makefile.am.
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = libs utils tests examples include 

# for make dist 
EXTRA_DIST=3rdparty/msgpack-c 3rdparty/websocketpp 3rdparty/apache/base64.h	\
3rdparty/http_parser/AUTHORS 3rdparty/http_parser/http_parser.c				\
3rdparty/http_parser/http_parser.h 3rdparty/http_parser/LICENSE-MIT			\
3rdparty/http_parser/README.md CHANGELOG.md scripts LICENSE			\
CMakeLists.txt cmake javascript


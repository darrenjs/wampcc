##
## Makefile template for compiling simple C/C++ programs
##
#----------------------------------------------------------------------

## Version 0.7
## July 2005

## The idea behind this file it to provide a template for use for simple
## C/C++ compilation processes. Importantly, this template file is never
## meant to replace the much more sophisticated automake and autoconf
## approach: they should be used whenever it becomes important that
## source code is distributed to other users / platforms, or when there
## a peculiar library or configuration prerequisites; this becomes an
## occasion for using a configure script.
##

## An aim of this file is be quickly usable in the sense that only a few
## changes needed to be make in order to use it for new C/C++
## programs. To further support usability, a makefile quick reference is
## provided at that end.

#----------------------------------------------------------------------

LIBUVHOME=/home/darrens/opt/libuv-1.8.0
LIBUVINC=-I$(LIBUVHOME)/include
LIBUVLIB=-L$(LIBUVHOME)/lib
LIBUVLIBSTATIC=$(LIBUVHOME)/lib/libuv.a


JANSSONHOME=/home/darrens/opt/jansson-2.7
JANSSONLIBSTATIC=$(JANSSONHOME)/lib/libjansson.a

JALSONHOME=/home/darrens/opt/jalson-1.0
JALSONINC=-I$(JALSONHOME)/include
JALSONLIB=-L$(JALSONHOME)/lib -ljalson
JALSONLIBSTATIC=$(JALSONHOME)/lib/libjalson.a $(JANSSONLIBSTATIC)


##
## Targets to build
##
BIN1=nexio
BIN2=admin
BIN3=client
TARGETS=$(BIN1) $(BIN2) $(BIN3)

##
## Sources that will need compiling
##
SOURCES_BIN1 =  session_state_listener.cc utils.cc NexioServer.cc SessionMan.cc Session.cc IOHandle.cc Topic.cc  TopicMan.cc Table.cc IOLoop.cc rpc_man.cc event_loop.cc  client_service.cc dealer_service.cc event.cc Logger.cc Callbacks.cc main.cc


##
## Sources that will need compiling
##
SOURCES_BIN2 =session_state_listener.cc   utils.cc NexioServer.cc SessionMan.cc Session.cc IOHandle.cc Topic.cc  TopicMan.cc Table.cc IOLoop.cc rpc_man.cc event_loop.cc  client_service.cc dealer_service.cc event.cc Logger.cc Callbacks.cc  admin.cc

##
## Sources that will need compiling
##
SOURCES_BIN3 = session_state_listener.cc  utils.cc NexioServer.cc SessionMan.cc Session.cc IOHandle.cc Topic.cc  TopicMan.cc Table.cc IOLoop.cc rpc_man.cc event_loop.cc client_service.cc dealer_service.cc event.cc Logger.cc  Callbacks.cc  client.cc



# "It is standard practice for every makefile to have a variable named
# objects, OBJECTS, objs, OBJS, obj, or OBJ which is a list of all
# object file names"
TEMP1=$(patsubst %.cc, %.o, $(SOURCES_BIN1))
OBJECTS_BIN1=$(patsubst %.c, %.o, $(TEMP1))
TEMP2=$(patsubst %.cc, %.o, $(SOURCES_BIN2))
OBJECTS_BIN2=$(patsubst %.c, %.o, $(TEMP2))
TEMP3=$(patsubst %.cc, %.o, $(SOURCES_BIN3))
OBJECTS_BIN3=$(patsubst %.c, %.o, $(TEMP3))

##
## List other files to be 'cleaned'
##
RUBBISH=$(OBJECTS_BIN1) $(OBJECTS_BIN2)  $(OBJECTS_BIN3) ${TARGETS} .depend

#----------------------------------------------------------------------
##
## Program options
##


#SANITIZE=-fsanitize=address  -fno-omit-frame-pointer

## Include path
INCPATH  = \
	-I.  $(LIBUVINC) $(JALSONINC)

## Compiler flags
CXXFLAGS = -O0 -g3  -Wall -W ${INCPATH} -D_REENTRANT -std=c++0x ${SANITIZE}

## Link flags
LIBS     = \
	$(LIBUVLIBSTATIC) \
	$(JALSONLIBSTATIC) \
	-L/home/${USER}/work/dev/build/linux/lib \
	-lpthread \
    -luv \
	-lcrypto

#----------------------------------------------------------------------
##
## Set the programs to use
##

CXX = clang++-3.5
AR  = ar

##
## QT tools
##

MOC = $(QTDIR)/bin/moc

#----------------------------------------------------------------------

##
## Edit this line to specify the intial target to build
##

all: $(TARGETS)

#----------------------------------------------------------------------

##
## Put rules for user specific targets in this section
##


#----------------------------------------------------------------------


${BIN1}: ${OBJECTS_BIN1}
	${CXX} -o $@ ${OBJECTS_BIN1}  ${LIBS} ${SANITIZE}

${BIN2}: ${OBJECTS_BIN2}
	${CXX} -o $@ ${OBJECTS_BIN2}  ${LIBS} ${SANITIZE}

${BIN3}: ${OBJECTS_BIN3}
	${CXX} -o $@ ${OBJECTS_BIN3}  ${LIBS} ${SANITIZE}


run: ${BIN1}
	./${BIN1} -s

.PHONY : clean
clean :
	rm -rf ${RUBBISH}

##
## Automatically generate dependencies. Whenever #include directives are
## added, deleted or changed in source files, we need to run "make depend"
##
depend: .depend

## Include the automatically generated dependency file. The minus before
## the include suppresses warnings if the .depend file does not exist;
## in which case this is ignored.
-include ./.depend
#----------------------------------------------------------------------

##
## Rule for generating out-style .depend file which contains a list of
## all dependencies
##
.depend:
	${CXX} ${CXXFLAGS} -MM $(SOURCES_BIN1) $(SOURCES_BIN2) > .depend

#----------------------------------------------------------------------
## Makefile Quick Reference
##
## Automatic Variables
## -------------------
##
##     $? prints only those dependencies that are newer than the target
##
##     $@ prints the file name of the target of the rule
##
##     $< prints the name of the first dependency
##
##     $^ prints all dependencies, with spaces between them
##
## Useful Functions
## ----------------
##
##     wildcard
##
## Use for wildcard expansion in variable assignments or inside
## arguments of a function. In such places write $(wildcard
## pattern...). ne use of the wildcard function is to get a list of all
## the C source files in a directory, like this: $(wildcard *.c) and we
## can change the list of C source files into a list of object files by
## replacing the `.c' suffix with `.o' in the result, like this:
## $(patsubst %.c,%.o,$(wildcard *.c))
##
##
##

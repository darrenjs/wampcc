
ifeq ($(XXX_HOME),)
 $(error XXX_HOME undefined - set XXX_HOME to where XXX was make-installed)
endif

ifeq ($(LIBUV_HOME),)
 $(error LIBUV_HOME undefined - set LIBUV_HOME to where libuv was make-installed)
endif

ifeq ($(JANSSON_HOME),)
 $(error JANSSON_HOME undefined - set JANSSON_HOME to where jansson was make-installed)
endif

XXX_INC=-I$(XXX_HOME)/include
XXX_LIBS=-L$(XXX_HOME)/lib -lXXX -ljalson

LIBUV_INC=-I$(LIBUV_HOME)/include
LIBUV_LIBS=-L$(LIBUV_HOME)/lib -luv

JANSSON_LIBS=-L$(JANSSON_HOME)/lib -ljansson

CXXFLAGS += -MMD -MP
CXXFLAGS += -Wall -O0 -g3 -ggdb -std=c++0x -pthread   $(XXX_INC) $(JALSON_INC) $(LIBUV_INC)

LDLIBS +=$(XXX_LIBS) $(LIBUV_LIBS) $(JALSON_LIBS) $(JANSSON_LIBS) -lcrypto -lpthread

# default: callee

all_srcs := $(shell find . -name \*.cc)
app_srcs := $(shell find . -name \*.cc)

all   : apps
apps  : $(app_srcs:%.cc=%)
test  : obj/test/main ; @$<
clean : ; rm -f $(app_srcs:%.cc=%) $(app_srcs:%.cc=%.d)

#-include $(all_srcs:%.cc=%.d)
.PRECIOUS : %.o

%.o            : %.cc ; $(COMPILE.cpp) $(OUTPUT_OPTION) $<
%              : %.o ; @$(LINK.cpp) $(OUTPUT_OPTION) $^  $(LDLIBS)

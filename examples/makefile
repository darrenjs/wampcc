
ifeq ($(XXX_HOME),)
 $(error XXX_HOME undefined - set XXX_HOME to where XXX was make-installed)
endif

XXX_INC=-I$(XXX_HOME)/include
XXX_LIBS=-L$(XXX_HOME)/lib -lXXX -ljalson
XXX_LIBA=$(XXX_HOME)/lib/libXXX.a

LIBUV_HOME=/home/darrens/opt/libuv-1.8.0
LIBUV_INC=-I$(LIBUV_HOME)/include
LIBUV_LIBS=-L$(LIBUV_HOME)/lib -luv
LIBUV_LIBA=$(LIBUV_HOME)/lib/libuv.a

JANSSON_HOME=/home/darrens/opt/jansson-2.7
JANSSON_LIBS=-L$(JANSSON_HOME)/lib -ljansson
JANSSON_LIBA=$(JANSSON_HOME)/lib/libjansson.a


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

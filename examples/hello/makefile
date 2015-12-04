CXX=g++

# specify installation location of JALSON.  Note we are linked statically here.
JALSONDIR=/home/darrens/jalson/install
JALSONINC=-I$(JALSONDIR)/include
JALSONLIB=$(JALSONDIR)/lib/libjalson.a

# specify installation location on JSON vendor implementation (in this case we
# are using Jansson), and we will also link statically
JANSSONDIR=/home/darrens/opt/jansson-2.7
JANSSONLIB=$(JANSSONDIR)/lib/libjansson.a

hello:hello.o
	$(CXX)  -o hello hello.o $(JALSONLIB)  $(JANSSONLIB)

hello.o:hello.cc
	$(CXX) $(JALSONINC) -Wall -g -c hello.cc

clean:
	rm -f hello hello.o

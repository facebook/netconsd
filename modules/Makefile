CC ?= gcc
CXX ?= g++
LDFLAGS ?=

override CFLAGS += -fPIC
override CXXFLAGS += -std=c++11 -fPIC
override LDFLAGS += -shared -static-libstdc++ -static-libgcc
INCLUDES = -I../ncrx -I../include

mods = printer.so logger.so

all: $(mods)

%.so: %.c
	$(CC) $< $(CFLAGS) $(INCLUDES) $(LDFLAGS) -c -o $(<:.c=.o)
	$(CC) $(<:.c=.o) $(CFLAGS) $(LDFLAGS) -o $@

%.so: %.cc
	$(CXX) $< $(CXXFLAGS) $(INCLUDES) $(LDFLAGS) -c -o $(<:.cc=.o)
	$(CXX) $(<:.cc=.o) $(CXXFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f *.o *.so

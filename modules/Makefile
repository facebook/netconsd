CC ?= gcc
CXX ?= g++
CPPFLAGS ?=
LDFLAGS ?=

override CFLAGS += -fPIC
override CXXFLAGS += -std=c++11 -fPIC
override LDFLAGS += -shared -static-libstdc++ -static-libgcc
INCLUDES = -I../ncrx -I../include

mods = printer.so logger.so

all: $(mods)

%.so: %.c
	$(CC) $< $(CPPFLAGS) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -c -o $(<:.c=.o)
	$(CC) $(<:.c=.o) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@

%.so: %.cc
	$(CXX) $< $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(LDFLAGS) -c -o $(<:.cc=.o)
	$(CXX) $(<:.cc=.o) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f *.o *.so

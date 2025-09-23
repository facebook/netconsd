CC ?= gcc
CXX ?= g++
CPPFLAGS ?=
LDFLAGS ?=

override CFLAGS += -fPIC
override CXXFLAGS += -std=c++14 -fPIC
override LDFLAGS += -shared
INCLUDES = -I../ncrx -I../include

# RE2 library linking
RE2_LIBS = -lre2

mods = printer.so logger-simple.so logger-advanced.so

all: $(mods)

%.so: %.c
	$(CC) $< $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c -o $(<:.c=.o)
	$(CC) $(<:.c=.o) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@

# Default rule for C++ files (without RE2)
%.so: %.cc
	$(CXX) $< $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) -c -o $(<:.cc=.o)
	$(CXX) $(<:.cc=.o) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -o $@

# Special rule for logger-advanced that needs RE2
logger-advanced.so: logger-advanced.cc
	$(CXX) $< $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) -c -o $(<:.cc=.o)
	$(CXX) $(<:.cc=.o) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $(RE2_LIBS) -o $@

clean:
	rm -f *.o *.so

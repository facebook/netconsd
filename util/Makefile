CFLAGS ?= -O2 -fPIC
CFLAGS += -D_GNU_SOURCE
CPPFLAGS ?=
LDFLAGS ?=
LIBS = -lpthread

all: netconsblaster

netconsblaster:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) netconsblaster.c $(LIBS) -o netconsblaster

clean:
	rm -f netconsblaster

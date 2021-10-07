CFLAGS ?= -O2 -fPIC
CFLAGS += -D_GNU_SOURCE
LDFLAGS ?= -shared
LIBS = -lpthread

all: netconsblaster

netconsblaster:
	$(CC) $(LDFLAGS) $(CFLAGS) netconsblaster.c $(LIBS) -o netconsblaster

CFLAGS ?= -O2 -fPIC
CFLAGS += -D_GNU_SOURCE
LDFLAGS ?=
LIBS = -lpthread

all: netconsblaster

netconsblaster:
	$(CC) $(CFLAGS) $(LDFLAGS) netconsblaster.c $(LIBS) -o netconsblaster

clean:
	rm -f netconsblaster

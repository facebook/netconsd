CC ?= gcc

CFLAGS ?= -O2 -fPIC
CFLAGS += -D_GNU_SOURCE -fno-strict-aliasing -Wall -Wextra \
          -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
          -Wdeclaration-after-statement -Wno-missing-field-initializers \
          -Wno-unused-function -Wno-unused-parameter
CPPFLAGS ?=

obj = libncrx.o

all: $(obj)

%.o: %.c
	$(CC) $< $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c -o $@

clean:
	rm -f *.o

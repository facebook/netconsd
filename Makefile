CC ?= gcc

LIBS = -lpthread -lrt -ldl
CFLAGS ?= -O2 -fPIC
CFLAGS += -D_GNU_SOURCE -fno-strict-aliasing -Wall -Wextra \
          -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
          -Wdeclaration-after-statement -Wno-missing-field-initializers \
          -Wno-unused-parameter
INCLUDES = -Incrx

debug debug32: CFLAGS += -O0 -gdwarf-4 -fno-omit-frame-pointer \
	                 -fstack-protector-all -fsanitize=address \
                         -fsanitize=undefined
debug debug32: LDFLAGS ?= -lasan -lubsan

32bit: CFLAGS += -m32
32bit: LDFLAGS ?= -m32

disasm: CFLAGS += -fverbose-asm

binary = netconsd
lib = ncrx/libncrx.o
liball = libnetconsd.a
obj = threads.o listener.o worker.o output.o main.o
rlibobj = threads.o listener.o worker.o output.o
asm = $(obj:.o=.s)

all: $(binary) mods
rlib: $(liball)
32bit: $(binary) mods

debug: all
debug32: 32bit
disasm: $(asm)

-include $(obj:.o=.d)

$(binary): $(lib) $(obj)
	$(CC) $(CFLAGS) $(LDFLAGS) $(lib) $(obj) $(LIBS) -o $@

$(liball): $(rlibobj) $(lib)
	ar rc $@ $(rlibobj) $(lib)

%.o: %.c
	$(CC) $< $(CFLAGS) $(INCLUDES) -c -o $@
	$(CC) -MM $< $(INCLUDES) > $(@:.o=.d)

%.s: %.c
	$(CC) $< $(CFLAGS) $(INCLUDES) -c -S -o $@

$(lib):
	$(MAKE) -e -C ncrx

mods:
	$(MAKE) -e -C modules

utils:
	$(MAKE) -e -C util

clean:
	rm -f netconsd *.o *.d *.s
	rm -f modules/*.o modules/*.so
	rm -f ncrx/*.o ncrx/*.d
	rm -f util/netconsblaster
	rm -f libnetconsd.a

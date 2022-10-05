# Netconsd: The Netconsole Daemon

[![Continuous Integration](https://github.com/facebook/netconsd/workflows/Continuous%20Integration/badge.svg?event=push)](https://github.com/facebook/netconsd/actions?query=workflow%3A%22Continuous+Integration%22)

This is a daemon for receiving and processing logs from the Linux Kernel, as
emitted over a network by the kernel's netconsole module. It supports both the
old "legacy" text-only format, and the new extended format added in v4.4.

The core of the daemon does nothing but process messages and drop them: in order
to make the daemon useful, the user must supply one or more "output modules".
These modules are shared object files which expose a small ABI that is called by
netconsd with the content and metadata for netconsole messages it receives.

This README explains how to build netconsd and use it with one of the existing
output modules in the modules/ directory. The end discusses how to write your
own custom output module.

## Building netconsd

The default Makefile target intended for production use has no external
dependencies besides glibc. To build it, just say `make`: you'll end up with a
single executable in this directory called `netconsd`, and a `*.so` file for every
module in the `modules/` directory.

The Makefile includes a few other handy targets:

* `debug`: Adds the usual debug flags, and also enables the ASAN and
           UBSAN sanitizers. You'll need to install libasan/libubsan on
           your system to build this target and run the binaries.
* `32bit`: Forces 32-bit compilation on x86_64 systems, for easily
           testing portability to 32-bit CPU architectures. You'll need
           to install 32-bit libraries if your distro doesn't have them.
* `debug32`: Union of the `32bit` and `debug` targets.
* `disasm`: Emits verbose annotated disassembly in `*.s` files.

If you want to build the daemon with clang, just append `CC="clang"` to your
make invocation. All the above targets should build with both clang and gcc.

## Running netconsd

### Setting up the server

By default, netconsd will use 1 listener and 2 worker threads, and listen on
port 1514 for messages. You can use `-l`, `-w`, and `-u` respectively to change
the defaults.

There's no universal wisdom about how many threads to use: just experiment with
different numbers and use netconsblaster to load up the server. Both the blaster
and the server will print how many packets they sent/processed.

If you run out of memory and OOM, you need more workers; if you see messages
being dropped, you need more listeners. The tuning here will obviously depend on
what your output module does: make sure to pass it when you do your testing.

For the simplest setup, just run:

```
$ make -s
$ ./netconsd ./modules/printer.so
```

Netconsd will always listen on `INADDR_ANY` and `IN6ADDR_ANY`. So far there's been
no reason to make that configurable: if you care, open an issue and we will.

### Setting up the client

The netconsole module takes a parameter like this:

```
netconsole=${sport}@${saddr}/${intf},${dport}@${daddr}/${dmac}
```

The fields are as follows:

1. `sport`: Source port for the netconsole UDP packets
2. `saddr`: Source address for the netconsole UDP packets
3. `intf`: The name of the interface to send the UDP packets from
4. `dport`: Destination port for the netconsole UDP packets
5. `daddr`: Destination address for the netconsole UDP packets
6. `dmac`: Destination L2 MAC address for the netconsole UDP packets

We need (6) because of how low-level netconsole is: it can't consult the routing
table to send the packet, so it must know a priori what MAC address to use in
the Ethernet frame it builds.

If you're talking to a server on the same L2 segment as the client, use the MAC
address of that server. Otherwise, use the MAC address of your router. You can
use the following quick shell one-liners to easily get the MAC of the router:

* IPv6: `ip -6 neighbor show | grep router`
* IPv4: `sudo arp –a | grep gateway`

Here are a couple examples for the parameter above:

```
IPv6: netconsole=+6666@2401:db00:11:801e:face:0:31:0/eth0,1514@2401:db00:11:d0be:face:0:1b:0/c0:8c:60:3d:0d:bc
IPv4: netconsole=6666@192.168.0.22/eth0,1514@192.168.0.1/00:00:0c:9f:f1:90
```

Prepending `+` to the cmdline will cause kernels that support it to use extended
netconsole, which you almost certainly want. Kernels too old to support extcon
will silently ignore the `+`.

Once you have your parameter constructed, just insert the module with it:

```
$ sudo modprobe netconsole netconsole=+6666@2401:db00:11:801e:face:0:31:0/eth0,1514@2401:db00:11:d0be:face:0:1b:0/c0:8c:60:3d:0d:bc
```

You're good to go!

### Testing on the client

Now that everything is running, you can use `/dev/kmsg` to write some logs:

```
$ sudo bash -c 'echo "Hello world!" > /dev/kmsg'
$ sudo bash -c 'echo "<0>OMG!" > /dev/kmsg'
```

The `<0>` tells the kernel what loglevel to use: 0 is `KERN_EMERG`, which ensures
your message will actually get transmitted.

## Writing an output module

### Interface to netconsd

Output modules are shared object files loaded with `dlopen()` at runtime by
netconsd. Netconsd will look for three functions in your module:

1. `int netconsd_output_init(int worker_thread_count)`
2. `void netconsd_output_handler(int thread, struct in6_addr *src, struct msgbuf *buf, struct ncrx_msg *msg)`
3. `void netconsd_output_exit(void)`

If (1) exists, it is called when your module is loaded: the argument tells you
how many worker threads netconsd is going to call your module from. If you
return non-zero from this function, netconsd will `abort()` and exit.

If (3) exists, it is called when netconsd unloads your module.

For every message it receives, netconsd will call (2) in your module. The code
must be reentrant: `netconsd_output_handler()` will be called concurrently from
all of the worker threads in netconsd. The `thread` argument tells you which
worker is invoking the function, which makes it easy to have per-thread data.

Netconsd uses a consistent hash to decide which worker to pass messages to, so
messages from same remote address will always be queued to the same thread.

The `src` argument will always point to an `in6_addr` struct containing the source
address of the netconsole packet. If the source was an IPv4 address, it will be
formatted like `::FFFF:<IPv4 address>` (see `man ipv6` for details).

If the message had extended metadata, `msg` will point to the `ncrx_msg` struct
containing that metadata and `buf` will be `NULL`. Otherwise, `msg` will be `NULL`
and `buf` will point to a `msgbuf` struct with the raw message text.

Output modules must not modify the structures passed in. The memory backing all
the pointers passed in will be freed immediately after the handler returns.

### Building the modules

For modules written in C this is trivial: just compile with `-shared`.

For modules written in C++ it can be a bit trickier: you will probably need to
build with `-static-libstdc++` and/or `-static-libgcc` to make this work.

See the code and Makefile in `modules/` for some examples of the above.

Chek out `rust/` if you are looking for an example of a netconsd module
written in Rust.

## Contributing

See the CONTRIBUTING file for how to help out.

## License

netconsd is BSD licensed, see the LICENSE file for more information.

netconsd was originally written by Calvin Owens as part of
[fbkutils](https://github.com/facebookarchive/fbkutils) in 2016, with later
contributions by several other people. This repository is a direct continuation
of that codebase.

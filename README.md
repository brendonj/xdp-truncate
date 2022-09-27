# XDP Truncation Example

Truncate received packets after any known headers, but before user payload.
Currently works for IPv4, IPv6, ICMPv4, ICMPv6, TCP and UDP. Packets of other
protocols will be passed unmodified.

## Dependencies

Semi-recent Linux with XDP enabled. To build on Ubuntu or Debian you'll
need something like:
```
$ sudo apt-get install build-essential clang llvm libbpf-dev gcc-multilib iproute2
```

## Compile
```
$ make
clang -O2 -g -Wall -Wno-compare-distinct-pointer-types -target bpf -c xdp_truncate.c -o xdp_truncate.o
```

## Using

Load:
```
 $ sudo ip link set dev eth0 xdp object xdp_truncate.o section truncate
```

Unload:
```
 $ sudo ip link set dev eth0 xdp off
```

## See Also:
 * https://github.com/xdp-project/xdp-tutorial
 * https://github.com/dpino/xdp_ipv6_filter
 * https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/
 * https://blogs.igalia.com/dpino/2019/01/10/the-express-data-path/

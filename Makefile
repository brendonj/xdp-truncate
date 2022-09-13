all: xdp_truncate.o

xdp_truncate.o: xdp_truncate.c
	clang -O2 -g -Wall -Wno-compare-distinct-pointer-types -target bpf -c xdp_truncate.c -o xdp_truncate.o

clean:
	rm -f xdp_truncate.o

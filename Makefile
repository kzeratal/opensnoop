APPS = opensnoop

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INI_CFLAGS := $(shell pkg-config --cflags inih)
INI_LIBS := $(shell pkg-config --libs inih)

all: $(APPS)

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

opensnoop: opensnoop.c opensnoop.skel.h
	$(CC) -g -O2 $(INI_CFLAGS) \
		opensnoop.c config.c -o opensnoop \
		-lbpf -lelf -lz $(INI_LIBS)

clean:
	rm -f *.bpf.o *.skel.h $(APPS)

.PHONY: all clean

APPS = opensnoop

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

all: $(APPS)

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

opensnoop: opensnoop.c opensnoop.skel.h
	$(CC) -g -O2 opensnoop.c -o opensnoop -lbpf -lelf -lz

clean:
	rm -f *.bpf.o *.skel.h $(APPS)

.PHONY: all clean

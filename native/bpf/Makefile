# Build eBPF object for Android GKI arm64 (run on Linux / WSL)
# Requirements: clang >= 12, llvm, linux kernel headers (GKI 5.10+), libbpf-dev
#
# Usage:
#   make                    # build cam_track.bpf.o
#   make vmlinux            # generate vmlinux.h from /sys/kernel/btf/vmlinux
#   make clean

CLANG      ?= clang
BPFTOOL    ?= bpftool
ARCH       := arm64
LINUX_HDRS ?= /usr/src/linux-headers-$(shell uname -r)

CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
          -I$(LINUX_HDRS)/include \
          -I/usr/include/$(ARCH)-linux-gnu \
          -mcpu=v3

all: cam_track.bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

cam_track.bpf.o: cam_track.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "Built: $@"

clean:
	rm -f cam_track.bpf.o vmlinux.h

.PHONY: all clean vmlinux

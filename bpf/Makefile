BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
BPF_CFLAGS = -O2 -g -target bpf

SRC = src/device_filter.c
OBJ = device_filter.bpf.o
VMLINUX_H = src/vmlinux.h
VMLINUX_H_GZ = src/vmlinux.h.gz

all: $(OBJ)

# Decompress vmlinux.h if needed
$(VMLINUX_H): $(VMLINUX_H_GZ)
	gunzip -c $< > $@

# Compile the BPF object
$(OBJ): $(SRC) $(VMLINUX_H)
	$(BPF_CLANG) $(BPF_CFLAGS) -I/usr/include -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

# Target to regenerate vmlinux.h.gz from running kernel BTF
vmlinux: $(VMLINUX_H_GZ)

$(VMLINUX_H_GZ):
	@echo "Generating src/vmlinux.h.gz from running kernel BTF..."
	@mkdir -p src
	bpftool btf dump file /sys/kernel/btf/vmlinux format c | gzip > $(VMLINUX_H_GZ)
	@echo "Done: $(VMLINUX_H_GZ)"

clean:
	rm -f $(OBJ) $(VMLINUX_H)

.PHONY: all clean vmlinux

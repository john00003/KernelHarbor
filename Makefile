TRACERS := execve-tracer open-tracer openat-tracer openat2-tracer
TRACER_BINS := $(foreach t,$(TRACERS),cmd/$(t)/$(t))
ANALYSIS_BIN := cmd/analysis/analysis

BPF_SRC := $(wildcard bpf/*.bpf.c bpf/*.h)
VMLINUX := bpf/vmlinux.h

.PHONY: all build generate vmlinux analysis tracers $(TRACERS) clean test

all: build

build: tracers analysis

# --- vmlinux.h ---

vmlinux: $(VMLINUX)

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# --- individual tracers ---

execve-tracer: $(VMLINUX)
	go generate ./cmd/execve-tracer/
	go build -o cmd/execve-tracer/execve-tracer ./cmd/execve-tracer

open-tracer: $(VMLINUX)
	go generate ./cmd/open-tracer/
	go build -o cmd/open-tracer/open-tracer ./cmd/open-tracer

openat-tracer: $(VMLINUX)
	go generate ./cmd/openat-tracer/
	go build -o cmd/openat-tracer/openat-tracer ./cmd/openat-tracer

openat2-tracer: $(VMLINUX)
	go generate ./cmd/openat2-tracer/
	go build -o cmd/openat2-tracer/openat2-tracer ./cmd/openat2-tracer

tracers: $(TRACERS)

# --- analysis ---

analysis:
	cd cmd/analysis && go build -o analysis .

# --- test ---

test:
	cd cmd/analysis && go test ./...

# --- clean ---

clean:
	rm -f $(TRACER_BINS) $(ANALYSIS_BIN)
	rm -f cmd/*/execvetracer_bpf*.go cmd/*/execvetracer_bpf*.o
	rm -f cmd/*/opentracer_bpf*.go cmd/*/opentracer_bpf*.o
	rm -f cmd/*/openattracer_bpf*.go cmd/*/openattracer_bpf*.o
	rm -f cmd/*/openat2tracer_bpf*.go cmd/*/openat2tracer_bpf*.o
	rm -f $(VMLINUX)

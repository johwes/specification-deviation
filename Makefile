# M0 sensor spike — build entry points.
# Prereqs: clang, llvm, bpftool, golang, make, libbpf-devel, kernel-headers
# (see Containerfile for a reproducible build environment).

GO ?= go

BIN := bin/sensor

.PHONY: all generate build vet clean

all: build

# Regenerates cmd/sensor/bpf_bpf*.go (gitignored) from bpf/egress.c via bpf2go.
generate:
	cd cmd/sensor && $(GO) generate

build: generate
	$(GO) build -o $(BIN) ./cmd/sensor

vet: generate
	$(GO) vet ./...

clean:
	rm -rf bin cmd/sensor/bpf_bpf*.go cmd/sensor/bpf_bpf*.o

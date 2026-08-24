# M0 sensor spike — build entry points.
# Prereqs: clang, llvm, bpftool, golang, make, libbpf-devel, kernel-headers
# (see Containerfile for a reproducible build environment).

GO ?= go

BIN := bin/sensor
PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: all generate build vet install clean

all: build

# Regenerates cmd/sensor/bpf_bpf*.go (gitignored) from bpf/egress.c via bpf2go.
generate:
	cd cmd/sensor && $(GO) generate

build: generate
	$(GO) build -o $(BIN) ./cmd/sensor

vet: generate
	$(GO) vet ./...

# Installs the M1.1 daemon as a systemd service. Intended for a target VM,
# not a dev sandbox -- run on the box you actually want the daemon on.
install: build
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/specdev-sensor
	install -Dm644 packaging/specdev-sensor.service $(DESTDIR)/usr/lib/systemd/system/specdev-sensor.service
	install -Dm644 packaging/sensor.json.example $(DESTDIR)/etc/specification-deviation/sensor.json.example

clean:
	rm -rf bin cmd/sensor/bpf_bpf*.go cmd/sensor/bpf_bpf*.o

# Reproducible build environment for the M0 sensor spike.
#
#   podman build -t specdev-build .
#   podman run --rm -v "$PWD:/src:Z" specdev-build make build
#
# Productization note: for a RHEL pipeline, swap the base image for
# registry.access.redhat.com/ubi9 plus go-toolset/clang packages. The build
# steps are identical — CO-RE keeps the compiled object portable across
# kernels with BTF.
FROM registry.fedoraproject.org/fedora:latest

RUN dnf install -y --setopt=install_weak_deps=False \
        clang llvm bpftool golang make git libbpf-devel kernel-headers \
    && dnf clean all

WORKDIR /src

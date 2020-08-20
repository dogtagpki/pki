ARG OS_VERSION=latest
FROM registry.fedoraproject.org/fedora:$OS_VERSION

# Install systemd since pki runs as a systemd service
RUN true \
        && dnf update -y --refresh \
        && dnf install -y systemd \
        && true

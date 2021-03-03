ARG OS_VERSION=latest
FROM registry.fedoraproject.org/fedora:$OS_VERSION

COPY build/RPMS /tmp/RPMS/

# Install PKI packages
RUN dnf install -y dnf-plugins-core \
        && dnf copr enable -y @pki/master \
        && dnf localinstall -y /tmp/RPMS/*

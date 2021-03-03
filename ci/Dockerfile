ARG OS_VERSION=latest

FROM registry.fedoraproject.org/fedora:$OS_VERSION
ARG COPR_REPO=@pki/master

COPY build/RPMS /tmp/RPMS/

# Install PKI packages
RUN dnf install -y dnf-plugins-core \
        && dnf copr enable -y $COPR_REPO \
        && dnf localinstall -y /tmp/RPMS/*

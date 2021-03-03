ARG OS_VERSION=latest

FROM registry.fedoraproject.org/fedora:$OS_VERSION AS builder
ARG COPR_REPO=@pki/master
ARG BUILD_OPTS

# Import PKI sources
COPY . /tmp/pki/
WORKDIR /tmp/pki

# Build PKI packages
RUN dnf install -y dnf-plugins-core rpm-build
RUN dnf copr enable -y $COPR_REPO
RUN dnf builddep -y --allowerasing --spec ./pki.spec --nogpgcheck
RUN ./build.sh $BUILD_OPTS --work-dir=build rpm

FROM registry.fedoraproject.org/fedora:$OS_VERSION
ARG COPR_REPO=@pki/master

# Import PKI packages
COPY --from=builder /tmp/pki/build/RPMS /tmp/RPMS/

# Install PKI packages
RUN dnf install -y dnf-plugins-core \
        && dnf copr enable -y $COPR_REPO \
        && dnf localinstall -y /tmp/RPMS/*

#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# https://docs.fedoraproject.org/en-US/containers/guidelines/guidelines/

ARG VENDOR="Dogtag"
ARG MAINTAINER="Dogtag PKI Team <devel@lists.dogtagpki.org>"
ARG COMPONENT="dogtag-pki"
ARG LICENSE="GPLv2 and LGPLv2"
ARG ARCH="x86_64"
ARG VERSION="0"
ARG OS_VERSION="latest"
ARG COPR_REPO="@pki/master"

FROM registry.fedoraproject.org/fedora:$OS_VERSION AS pki-runner

ARG COPR_REPO

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Import PKI packages
COPY build/RPMS /tmp/RPMS/

# Install PKI packages
RUN dnf localinstall -y /tmp/RPMS/*; rm -rf /tmp/RPMS

# Install IPA packages
RUN dnf copr enable -y @freeipa/freeipa-master-nightly
RUN dnf install -y freeipa-server freeipa-server-dns freeipa-healthcheck freeipa-client \
    certbot python3-ipatests

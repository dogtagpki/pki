#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# https://docs.fedoraproject.org/en-US/containers/guidelines/guidelines/

FROM registry.fedoraproject.org/fedora:40

ARG NAME="pki-ca"
ARG SUMMARY="Dogtag PKI Certificate Authority"
ARG LICENSE="GPLv2 and LGPLv2"
ARG VERSION="0"
ARG ARCH="x86_64"
ARG MAINTAINER="Dogtag PKI Team <devel@lists.dogtagpki.org>"
ARG VENDOR="Dogtag"
ARG COMPONENT="dogtag-pki"
ARG COPR_REPO=""

LABEL name="$NAME" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 $NAME" \
      com.redhat.component="$COMPONENT"

EXPOSE 8080 8443

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Install packages
RUN dnf install -y rpm-build \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# Import PKI sources
COPY . /tmp/pki/
WORKDIR /tmp/pki

# Build and install PKI packages
RUN dnf builddep -y --spec pki.spec \
    && ./build.sh --with-pkgs=base,server,ca --work-dir=build rpm \
    && dnf localinstall -y build/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf build

# Create PKI server
RUN pki-server create --group root

# Create NSS database
RUN pki-server nss-create --no-password

VOLUME [ "/certs" ]

CMD [ "/usr/share/pki/ca/bin/pki-ca-run" ]

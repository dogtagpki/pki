#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# https://docs.fedoraproject.org/en-US/containers/guidelines/guidelines/

FROM registry.fedoraproject.org/fedora:41

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

# Install packages
RUN dnf install -y dnf-plugins-core \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf copr enable -y $COPR_REPO; fi

# Import PKI sources
COPY . /tmp/pki/
WORKDIR /tmp/pki

# Build and install PKI packages
RUN dnf install -y rpm-build \
    && dnf builddep -y --spec pki.spec \
    && ./build.sh --with-pkgs=base,server,ca --work-dir=build rpm \
    && dnf localinstall -y build/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf build

# In OpenShift the server runs as an OpenShift-assigned user
# (with a random UID) that belongs to the root group (GID=0),
# so the server instance needs to be owned by the root group.
#
# https://www.redhat.com/en/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id

# Create PKI server
RUN pki-server create \
    --group root \
    --conf /data/conf \
    --logs /data/logs

# In Docker/Podman the server runs as pkiuser (UID=17). To
# ensure it generates files with the proper ownership the
# pkiuser's primary group needs to be changed to the root
# group (GID=0).

# Change pkiuser's primary group to root group
RUN usermod pkiuser -g root

# Create NSS database
RUN pki-server nss-create --no-password

# Create CA subsystem
RUN pki-server ca-create

# Deploy CA subsystem
RUN pki-server ca-deploy

# Store default config files
RUN mv /data/conf /var/lib/pki/pki-tomcat/conf.default

# Grant the root group the full access to PKI server files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chgrp -Rf root /var/lib/pki/pki-tomcat
RUN chmod -Rf g+rw /var/lib/pki/pki-tomcat

VOLUME [ "/certs", "/data" ]

CMD [ "/usr/share/pki/ca/bin/pki-ca-run" ]

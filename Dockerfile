#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# https://docs.fedoraproject.org/en-US/containers/guidelines/guidelines/

ARG OS_VERSION="latest"

################################################################################
FROM registry.fedoraproject.org/fedora:$OS_VERSION AS pki-builder

ARG COPR_REPO
ARG BUILD_OPTS

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Import PKI sources
COPY . /tmp/pki/
WORKDIR /tmp/pki

# Build PKI packages
RUN dnf install -y rpm-build
RUN dnf builddep -y --spec pki.spec
RUN ./build.sh $BUILD_OPTS --work-dir=build rpm

################################################################################
FROM registry.fedoraproject.org/fedora:$OS_VERSION AS pki-runner

ARG COPR_REPO

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Import PKI packages
COPY --from=pki-builder /tmp/pki/build/RPMS /tmp/RPMS/

# Install PKI packages
RUN dnf localinstall -y /tmp/RPMS/*; rm -rf /tmp/RPMS

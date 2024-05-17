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
ARG BASE_IMAGE="registry.fedoraproject.org/fedora:latest"
ARG COPR_REPO=""
ARG BUILD_OPTS=""

################################################################################
FROM $BASE_IMAGE AS pki-base

RUN dnf install -y dnf-plugins-core systemd \
    && dnf clean all \
    && rm -rf /var/cache/dnf

CMD [ "/usr/sbin/init" ]

################################################################################
FROM pki-base AS pki-deps

ARG COPR_REPO

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf copr enable -y $COPR_REPO; fi

# Install PKI runtime dependencies
RUN dnf install -y dogtag-pki \
    && rpm -e --nodeps $(rpm -qa | grep -E "^java-|^dogtag-|^python3-dogtag-") \
    && dnf clean all \
    && rm -rf /var/cache/dnf

################################################################################
FROM pki-deps AS pki-builder-deps

# Install build tools
RUN dnf install -y rpm-build

# Import PKI sources
COPY pki.spec /root/pki/
WORKDIR /root/pki

# Install PKI build dependencies
RUN dnf builddep -y --skip-unavailable --spec pki.spec

################################################################################
FROM pki-builder-deps AS pki-builder

ARG BUILD_OPTS

# Import JSS packages
COPY --from=quay.io/dogtagpki/jss-dist:latest /root/RPMS /tmp/RPMS/

# Import LDAP SDK packages
COPY --from=quay.io/dogtagpki/ldapjdk-dist:latest /root/RPMS /tmp/RPMS/

# Install build dependencies
RUN dnf localinstall -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS

# Import PKI sources
COPY . /root/pki/

# Build PKI packages
RUN ./build.sh --work-dir=build $BUILD_OPTS rpm

################################################################################
FROM alpine:latest AS pki-dist

# Import PKI packages
COPY --from=pki-builder /root/pki/build/SRPMS /root/SRPMS/
COPY --from=pki-builder /root/pki/build/RPMS /root/RPMS/

################################################################################
FROM pki-deps AS pki-runner

# Import JSS packages
COPY --from=quay.io/dogtagpki/jss-dist:latest /root/RPMS /tmp/RPMS/

# Import LDAP SDK packages
COPY --from=quay.io/dogtagpki/ldapjdk-dist:latest /root/RPMS /tmp/RPMS/

# Import PKI packages
COPY --from=pki-dist /root/RPMS /tmp/RPMS/

# Install runtime packages
RUN dnf localinstall -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS

################################################################################
FROM pki-runner AS pki-server

ARG SUMMARY="Dogtag PKI Server"

LABEL name="pki-server" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-server" \
      com.redhat.component="$COMPONENT"

EXPOSE 8080 8443

# Create PKI server
RUN pki-server create tomcat@pki --user tomcat --group root

# Create NSS database
RUN pki-server nss-create -i tomcat@pki --no-password

# Enable JSS
RUN pki-server jss-enable -i tomcat@pki

# Configure SSL connector
RUN pki-server http-connector-add -i tomcat@pki \
  --port 8443 \
  --scheme https \
  --secure true \
  --sslEnabled true \
  --sslProtocol SSL \
  --sslImpl org.dogtagpki.jss.tomcat.JSSImplementation \
  Secure

# Configure SSL server certificate
RUN pki-server http-connector-cert-add -i tomcat@pki \
  --keyAlias sslserver \
  --keystoreType pkcs11 \
  --keystoreProvider Mozilla-JSS

# Grant the root group the full access to PKI server files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chgrp -Rf root /var/lib/tomcats/pki
RUN chmod -Rf g+rw /var/lib/tomcats/pki

CMD [ "/usr/share/pki/server/bin/pki-server-run" ]

################################################################################
FROM pki-runner AS pki-ca

ARG SUMMARY="Dogtag PKI Certificate Authority"

LABEL name="pki-ca" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-ca" \
      com.redhat.component="$COMPONENT"

EXPOSE 8080 8443

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

VOLUME [ "/certs", "/data" ]

CMD [ "/usr/share/pki/ca/bin/pki-ca-run" ]

################################################################################
FROM pki-server AS pki-acme

ARG SUMMARY="Dogtag PKI ACME Responder"

LABEL name="pki-acme" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-acme" \
      com.redhat.component="$COMPONENT"

# Install PKI dependencies
RUN dnf install -y bind-utils iputils abrt-java-connector postgresql postgresql-jdbc

# Install PostgreSQL JDBC driver
RUN ln -s /usr/share/java/postgresql-jdbc/postgresql.jar /usr/share/pki/server/common/lib/postgresql.jar

# Create PKI ACME application
RUN pki-server acme-create -i tomcat@pki

# Use in-memory database by default
RUN cp /usr/share/pki/acme/database/in-memory/database.conf /var/lib/tomcats/pki/conf/acme

# Use NSS issuer by default
RUN cp /usr/share/pki/acme/issuer/nss/issuer.conf /var/lib/tomcats/pki/conf/acme

# Use in-memory realm by default
RUN cp /usr/share/pki/acme/realm/in-memory/realm.conf /var/lib/tomcats/pki/conf/acme

# Remove PKI ACME web application logging.properties so the logs will appear on the console
RUN rm -f /usr/share/pki/acme/webapps/acme/WEB-INF/classes/logging.properties

# Deploy PKI ACME application
RUN pki-server acme-deploy -i tomcat@pki

# Grant the root group the full access to PKI ACME files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chgrp -Rf root /var/lib/tomcats/pki
RUN chmod -Rf g+rw /var/lib/tomcats/pki

VOLUME [ \
    "/certs", \
    "/metadata", \
    "/database", \
    "/issuer", \
    "/realm" ]

CMD [ "/usr/share/pki/acme/bin/pki-acme-run" ]

################################################################################
FROM pki-runner AS ipa-runner

# Install IPA packages
RUN dnf copr enable -y @freeipa/freeipa-master-nightly \
    && dnf install -y freeipa-server freeipa-server-dns freeipa-healthcheck freeipa-client \
           python3-ipatests certbot \
    && dnf clean all \
    && rm -rf /var/cache/dnf

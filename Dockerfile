#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# https://docs.fedoraproject.org/en-US/containers/guidelines/guidelines/

ARG VENDOR="Dogtag"
ARG MAINTAINER="Dogtag PKI Team <devel@lists.dogtagpki.org>"
ARG COMPONENT="pki-core"
ARG LICENSE="GPLv2 and LGPLv2"
ARG ARCH="x86_64"
ARG VERSION="0"
ARG OS_VERSION="latest"
ARG COPR_REPO="@pki/master"

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
RUN dnf install -y git rpm-build
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

################################################################################
FROM registry.fedoraproject.org/fedora:$OS_VERSION AS pki-acme

ARG SUMMARY="Dogtag PKI ACME Responder"
ARG COPR_REPO

LABEL name="pki-acme" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-acme" \
      com.redhat.component="$COMPONENT"

EXPOSE 8080 8443

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Install PKI dependencies
RUN dnf install -y bind-utils iputils abrt-java-connector postgresql postgresql-jdbc

# Import PKI packages
COPY --from=pki-builder /tmp/pki/build/RPMS /tmp/RPMS/

# Install PKI packages
RUN dnf localinstall -y /tmp/RPMS/*; rm -rf /tmp/RPMS

# Install PostgreSQL JDBC driver
RUN ln -s /usr/share/java/postgresql-jdbc/postgresql.jar /usr/share/pki/server/common/lib/postgresql.jar

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
  --sslImpl org.dogtagpki.tomcat.JSSImplementation \
  Secure

# Configure SSL server certificate
RUN pki-server http-connector-cert-add -i tomcat@pki \
  --keyAlias sslserver \
  --keystoreType pkcs11 \
  --keystoreProvider Mozilla-JSS

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
    "/var/lib/tomcats/pki/conf/certs", \
    "/var/lib/tomcats/pki/conf/acme/metadata", \
    "/var/lib/tomcats/pki/conf/acme/database", \
    "/var/lib/tomcats/pki/conf/acme/issuer", \
    "/var/lib/tomcats/pki/conf/acme/realm" ]

CMD [ "/usr/share/pki/acme/bin/pki-acme-run" ]

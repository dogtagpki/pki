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
    && REGEX="^java-|^dogtag-|^python3-dogtag-" \
    && REGEX="$REGEX|^apache-commons-cli-|^apache-commons-codec-|^apache-commons-io-|^apache-commons-lang3-|^apache-commons-logging-|^apache-commons-net-" \
    && REGEX="$REGEX|^httpcomponents-|^slf4j-" \
    && REGEX="$REGEX|^jakarta-activation-|^jakarta-annotations-|^jaxb-api-" \
    && REGEX="$REGEX|^jboss-logging-|^jboss-jaxrs-2.0-api-" \
    && REGEX="$REGEX|^jackson-|^pki-resteasy-" \
    && rpm -e --nodeps $(rpm -qa | grep -E "$REGEX") \
    && dnf clean all \
    && rm -rf /var/cache/dnf

################################################################################
FROM pki-deps AS pki-builder-deps

# Import PKI sources
COPY pki.spec /root/pki/
WORKDIR /root/pki

# Install PKI build dependencies
RUN dnf install -y rpm-build \
    && dnf builddep -y --skip-unavailable pki.spec \
    && rpm -e --nodeps $(rpm -qa | grep -E "^dogtag-|^python3-dogtag-") \
    && dnf clean all \
    && rm -rf /var/cache/dnf

################################################################################
FROM pki-builder-deps AS pki-builder

ARG BUILD_OPTS

# Import JSS packages
COPY --from=quay.io/dogtagpki/jss-dist:latest /root/RPMS /tmp/RPMS/

# Import LDAP SDK packages
COPY --from=quay.io/dogtagpki/ldapjdk-dist:latest /root/RPMS /tmp/RPMS/

# Install build dependencies
RUN dnf install -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS

# Import PKI sources
COPY . /root/pki/

# Build PKI packages
RUN ./build.sh  --work-dir=build $BUILD_OPTS rpm

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
RUN dnf install -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS

# Update home directory owner
RUN chown -R pkiuser:pkiuser /home/pkiuser

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

# In OpenShift the server runs as an OpenShift-assigned user
# (with a random UID) that belongs to the root group (GID=0),
# so the server instance needs to be owned by the root group.
#
# https://www.redhat.com/en/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id

# Create PKI server
RUN pki-server create \
    --group root \
    --conf /conf \
    --logs /logs

# In Docker/Podman the server runs as pkiuser (UID=17). To
# ensure it generates files with the proper ownership the
# pkiuser's primary group needs to be changed to the root
# group (GID=0).

# Change pkiuser's primary group to root group
RUN usermod pkiuser -g root

# Create NSS database
RUN pki-server nss-create --no-password

# Enable JSS
RUN pki-server jss-enable

# Configure SSL connector
RUN pki-server http-connector-add \
  --port 8443 \
  --scheme https \
  --secure true \
  --sslEnabled true \
  --sslProtocol SSL \
  --sslImpl org.dogtagpki.jss.tomcat.JSSImplementation \
  Secure

# Configure SSL server certificate
RUN pki-server http-connector-cert-add \
  --keyAlias sslserver \
  --keystoreType pkcs11 \
  --keystoreProvider Mozilla-JSS

# Deploy ROOT webapp
RUN pki-server webapp-deploy \
  --descriptor /usr/share/pki/server/conf/Catalina/localhost/ROOT.xml \
  ROOT

# Deploy PKI webapp
RUN pki-server webapp-deploy \
  --descriptor /usr/share/pki/server/conf/Catalina/localhost/pki.xml \
  pki

# Store default config files
RUN cp -r /conf /var/lib/pki/pki-tomcat/conf.default

# Grant the root group the full access to PKI server files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chown -Rf pkiuser:root /var/lib/pki/pki-tomcat
RUN chmod -Rf g+rw /var/lib/pki/pki-tomcat

VOLUME [ "/certs", "/conf", "/logs" ]

CMD [ "/usr/share/pki/server/bin/pki-server-run" ]

################################################################################
FROM pki-server AS pki-ca

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

# Create CA subsystem
RUN pki-server ca-create

# Deploy CA subsystem
RUN pki-server ca-deploy

# Store additional default config files
RUN cp -r /conf/* /var/lib/pki/pki-tomcat/conf.default

# Grant the root group the full access to PKI server files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chown -Rf pkiuser:root /var/lib/pki/pki-tomcat
RUN chmod -Rf g+rw /var/lib/pki/pki-tomcat

CMD [ "/usr/share/pki/ca/bin/pki-ca-run" ]

################################################################################
FROM pki-server AS pki-kra

ARG SUMMARY="Dogtag PKI Key Recovery Authority"

LABEL name="pki-kra" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-kra" \
      com.redhat.component="$COMPONENT"

# Create KRA subsystem
RUN pki-server kra-create

# Deploy KRA subsystem
RUN pki-server kra-deploy

# Store additional default config files
RUN cp -r /conf/* /var/lib/pki/pki-tomcat/conf.default

# Grant the root group the full access to PKI server files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chown -Rf pkiuser:root /var/lib/pki/pki-tomcat
RUN chmod -Rf g+rw /var/lib/pki/pki-tomcat

CMD [ "/usr/share/pki/kra/bin/pki-kra-run" ]

################################################################################
FROM pki-server AS pki-ocsp

ARG SUMMARY="Dogtag PKI OCSP Responder"

LABEL name="pki-ocsp" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-ocsp" \
      com.redhat.component="$COMPONENT"

# Create OCSP subsystem
RUN pki-server ocsp-create

# Deploy OCSP subsystem
RUN pki-server ocsp-deploy

# Store additional default config files
RUN cp -r /conf/* /var/lib/pki/pki-tomcat/conf.default

# Grant the root group the full access to PKI server files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chown -Rf pkiuser:root /var/lib/pki/pki-tomcat
RUN chmod -Rf g+rw /var/lib/pki/pki-tomcat

CMD [ "/usr/share/pki/ocsp/bin/pki-ocsp-run" ]

################################################################################
FROM pki-server AS pki-tks

ARG SUMMARY="Dogtag PKI TKS"

LABEL name="pki-tks" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-tks" \
      com.redhat.component="$COMPONENT"

# Create TKS subsystem
RUN pki-server tks-create

# Deploy TKS subsystem
RUN pki-server tks-deploy

# Store additional default config files
RUN cp -r /conf/* /var/lib/pki/pki-tomcat/conf.default

# Grant the root group the full access to PKI server files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chown -Rf pkiuser:root /var/lib/pki/pki-tomcat
RUN chmod -Rf g+rw /var/lib/pki/pki-tomcat

CMD [ "/usr/share/pki/tks/bin/pki-tks-run" ]

################################################################################
FROM pki-server AS pki-tps

ARG SUMMARY="Dogtag PKI TPS"

LABEL name="pki-tps" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-tps" \
      com.redhat.component="$COMPONENT"

# Create TPS subsystem
RUN pki-server tps-create

# Deploy TPS subsystem
RUN pki-server tps-deploy

# Store additional default config files
RUN cp -r /conf/* /var/lib/pki/pki-tomcat/conf.default

# Grant the root group the full access to PKI server files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chown -Rf pkiuser:root /var/lib/pki/pki-tomcat
RUN chmod -Rf g+rw /var/lib/pki/pki-tomcat

CMD [ "/usr/share/pki/tps/bin/pki-tps-run" ]

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
RUN dnf install -y bind-utils iputils postgresql postgresql-jdbc

# Install PostgreSQL JDBC driver
RUN ln -s /usr/share/java/postgresql-jdbc/postgresql.jar /usr/share/pki/server/common/lib/postgresql.jar

# Create PKI ACME application
RUN pki-server acme-create

# Use in-memory database by default
RUN cp /usr/share/pki/acme/database/in-memory/database.conf /var/lib/pki/pki-tomcat/conf/acme

# Use NSS issuer by default
RUN cp /usr/share/pki/acme/issuer/nss/issuer.conf /var/lib/pki/pki-tomcat/conf/acme

# Use in-memory realm by default
RUN cp /usr/share/pki/acme/realm/in-memory/realm.conf /var/lib/pki/pki-tomcat/conf/acme

# Remove PKI ACME web application logging.properties so the logs will appear on the console
RUN rm -f /usr/share/pki/acme/webapps/acme/WEB-INF/classes/logging.properties

# Deploy PKI ACME application
RUN pki-server acme-deploy

# Store additional default config files
RUN cp -r /conf/* /var/lib/pki/pki-tomcat/conf.default

# Grant the root group the full access to PKI ACME files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chown -Rf pkiuser:root /var/lib/pki/pki-tomcat
RUN chmod -Rf g+rw /var/lib/pki/pki-tomcat

VOLUME [ \
    "/certs", \
    "/metadata", \
    "/database", \
    "/issuer", \
    "/realm", \
    "/conf", \
    "/logs" ]

CMD [ "/usr/share/pki/acme/bin/pki-acme-run" ]

################################################################################
FROM pki-builder-deps AS pki-quarkus-builder

ARG BUILD_OPTS

# Import JSS packages
COPY --from=quay.io/dogtagpki/jss-dist:latest /root/RPMS /tmp/RPMS/

# Import LDAP SDK packages
COPY --from=quay.io/dogtagpki/ldapjdk-dist:latest /root/RPMS /tmp/RPMS/

# Install build dependencies
RUN dnf install -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS

# Import PKI sources
COPY . /root/pki/

# Prepare sources the same way the RPM %prep section does:
# 1. Migrate source from javax to jakarta (needed for Fedora 43+ / Tomcat 10+)
# 2. Install pki-local:jboss-jaxrs-api_2.0_spec into ~/.m2 so Maven can resolve it
RUN cd /root/pki \
    && /usr/bin/javax2jakarta -profile=EE -exclude=./base/tomcat-9.0 ./base ./base \
    && JAXRS_VERSION=$(rpm -q jboss-jaxrs-2.0-api | sed -n 's/^jboss-jaxrs-2.0-api-\([^-]*\)-.*$/\1.Final/p') \
    && cp /usr/share/java/jboss-jaxrs-2.0-api.jar jboss-jaxrs-api_2.0_spec-$JAXRS_VERSION.jar \
    && /usr/bin/javax2jakarta -profile=EE jboss-jaxrs-api_2.0_spec-$JAXRS_VERSION.jar jboss-jaxrs-api_2.0_spec-$JAXRS_VERSION.jar \
    && mkdir -p ~/.m2/repository/pki-local/jboss-jaxrs-api_2.0_spec/$JAXRS_VERSION \
    && cp jboss-jaxrs-api_2.0_spec-$JAXRS_VERSION.jar ~/.m2/repository/pki-local/jboss-jaxrs-api_2.0_spec/$JAXRS_VERSION/jboss-jaxrs-api_2.0_spec-$JAXRS_VERSION.jar \
    && rm -f jboss-jaxrs-api_2.0_spec-$JAXRS_VERSION.jar

# Build all modules (including Quarkus) via Maven.
# This stage runs in parallel with pki-builder since both inherit from
# pki-builder-deps and BuildKit can schedule them concurrently.
RUN cd /root/pki \
    && mvn install -DskipTests -ntp

################################################################################
FROM pki-base AS pki-quarkus-runner

ARG COPR_REPO

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf copr enable -y $COPR_REPO; fi

# Import JSS packages
COPY --from=quay.io/dogtagpki/jss-dist:latest /root/RPMS /tmp/RPMS/

# Import LDAP SDK packages
COPY --from=quay.io/dogtagpki/ldapjdk-dist:latest /root/RPMS /tmp/RPMS/

# Install minimal runtime dependencies for Quarkus
RUN dnf install -y \
    java-17-openjdk-headless \
    nss \
    nss-tools \
    openldap-clients \
    curl \
    /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS

# Create pkiuser for Quarkus runtime
RUN groupadd -r pkiuser \
    && useradd -r -g pkiuser -d /home/pkiuser -s /sbin/nologin pkiuser \
    && mkdir -p /home/pkiuser \
    && chown -R pkiuser:pkiuser /home/pkiuser

# Install Quarkus runner JARs from builder
# Each *-quarkus module produces a quarkus-app/ directory with the uber-jar
COPY --from=pki-quarkus-builder /root/pki/base/est-quarkus/target/quarkus-app/ /usr/share/pki/quarkus/est/
COPY --from=pki-quarkus-builder /root/pki/base/acme-quarkus/target/quarkus-app/ /usr/share/pki/quarkus/acme/
COPY --from=pki-quarkus-builder /root/pki/base/ocsp-quarkus/target/quarkus-app/ /usr/share/pki/quarkus/ocsp/
COPY --from=pki-quarkus-builder /root/pki/base/kra-quarkus/target/quarkus-app/ /usr/share/pki/quarkus/kra/
COPY --from=pki-quarkus-builder /root/pki/base/tks-quarkus/target/quarkus-app/ /usr/share/pki/quarkus/tks/
COPY --from=pki-quarkus-builder /root/pki/base/tps-quarkus/target/quarkus-app/ /usr/share/pki/quarkus/tps/
COPY --from=pki-quarkus-builder /root/pki/base/ca-quarkus/target/quarkus-app/ /usr/share/pki/quarkus/ca/

# Copy shared libraries
COPY --from=pki-quarkus-builder /root/pki/base/server-core/target/pki-server-core-*.jar /usr/share/pki/lib/
COPY --from=pki-quarkus-builder /root/pki/base/quarkus-common/target/pki-quarkus-common-*.jar /usr/share/pki/lib/

# Copy systemd unit files
COPY --from=pki-quarkus-builder /root/pki/base/server/share/lib/systemd/system/pki-quarkusd@.service /usr/lib/systemd/system/
COPY --from=pki-quarkus-builder /root/pki/base/server/share/lib/systemd/system/pki-quarkusd.target /usr/lib/systemd/system/

EXPOSE 8080 8443

################################################################################
FROM pki-quarkus-runner AS pki-quarkus-ca

ARG SUMMARY="Dogtag PKI Certificate Authority (Quarkus)"

LABEL name="pki-quarkus-ca" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-quarkus-ca" \
      com.redhat.component="$COMPONENT"

CMD [ "java", "-jar", "/usr/share/pki/quarkus/ca/quarkus-run.jar" ]

################################################################################
FROM pki-quarkus-runner AS pki-quarkus-est

ARG SUMMARY="Dogtag PKI EST Subsystem (Quarkus)"

LABEL name="pki-quarkus-est" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-quarkus-est" \
      com.redhat.component="$COMPONENT"

CMD [ "java", "-jar", "/usr/share/pki/quarkus/est/quarkus-run.jar" ]

################################################################################
FROM pki-quarkus-runner AS pki-quarkus-acme

ARG SUMMARY="Dogtag PKI ACME Responder (Quarkus)"

LABEL name="pki-quarkus-acme" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-quarkus-acme" \
      com.redhat.component="$COMPONENT"

CMD [ "java", "-jar", "/usr/share/pki/quarkus/acme/quarkus-run.jar" ]

################################################################################
FROM pki-quarkus-runner AS pki-quarkus-ocsp

ARG SUMMARY="Dogtag PKI OCSP Responder (Quarkus)"

LABEL name="pki-quarkus-ocsp" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-quarkus-ocsp" \
      com.redhat.component="$COMPONENT"

CMD [ "java", "-jar", "/usr/share/pki/quarkus/ocsp/quarkus-run.jar" ]

################################################################################
FROM pki-quarkus-runner AS pki-quarkus-kra

ARG SUMMARY="Dogtag PKI Key Recovery Authority (Quarkus)"

LABEL name="pki-quarkus-kra" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-quarkus-kra" \
      com.redhat.component="$COMPONENT"

CMD [ "java", "-jar", "/usr/share/pki/quarkus/kra/quarkus-run.jar" ]

################################################################################
FROM pki-quarkus-runner AS pki-quarkus-tks

ARG SUMMARY="Dogtag PKI Token Key Service (Quarkus)"

LABEL name="pki-quarkus-tks" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-quarkus-tks" \
      com.redhat.component="$COMPONENT"

CMD [ "java", "-jar", "/usr/share/pki/quarkus/tks/quarkus-run.jar" ]

################################################################################
FROM pki-quarkus-runner AS pki-quarkus-tps

ARG SUMMARY="Dogtag PKI Token Processing System (Quarkus)"

LABEL name="pki-quarkus-tps" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 pki-quarkus-tps" \
      com.redhat.component="$COMPONENT"

CMD [ "java", "-jar", "/usr/share/pki/quarkus/tps/quarkus-run.jar" ]

################################################################################
FROM pki-runner AS ipa-runner

# Install IPA packages
RUN dnf copr enable -y @freeipa/freeipa-master-nightly \
    && dnf install -y freeipa-server freeipa-server-dns freeipa-healthcheck freeipa-client \
           python3-ipatests certbot \
    && dnf clean all \
    && rm -rf /var/cache/dnf

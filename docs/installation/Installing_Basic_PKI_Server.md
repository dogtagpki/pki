# Installing Basic PKI Server

## Overview

This page describes the process to create and configure a basic PKI server without any of the PKI subsystems.
This would be useful to troubleshoot infrastructure issues (e.g. SSL in Tomcat) without the complexity of a fully functional PKI server.

## Installation

```
$ dnf install pki-server
```

## Creating Tomcat Instance

To create Tomcat instance:

```
$ pki-server create tomcat@pki
```

This will create a Tomcat instance in /var/lib/tomcats/pki.

See also [PKI Server CLI](https://www.dogtagpki.org/wiki/PKI_Server_CLI).

## Configuring SSL Connector

To configure SSL connector, execute the following command:

```
$ pki-server http-connector-add -i tomcat@pki Secure \
    --port 8443 \
    --scheme https \
    --secure true \
    --sslEnabled true \
    --sslProtocol SSL
```

This will create the Connector and SSLHost elements in /var/lib/tomcats/pki/conf/server.xml.

See also [PKI Server HTTP Connector CLI](https://www.dogtagpki.org/wiki/PKI_Server_HTTP_Connector_CLI).

## Configuring SSL Certificate

There are several ways to provide an SSL certificate to Tomcat:

 - with PEM files
 - with JKS keystore
 - with PKCS \#12 keystore
 - with PKCS \#11 keystore

The following procedure will generate the certificate and add a Certificate element in /var/lib/tomcats/pki/conf/server.xml.

### Configuring SSL Certificate with PEM Files

To generate SSL certificate and key in PEM files:

```
$ openssl req -newkey rsa:2048 \
    -x509 \
    -nodes \
    -days 365 \
    -out /var/lib/tomcats/pki/conf/sslserver.crt \
    -keyout /var/lib/tomcats/pki/conf/sslserver.key \
    -subj "/CN=$HOSTNAME"
$ chown tomcat.tomcat /var/lib/tomcats/pki/conf/sslserver.crt
$ chmod 660 /var/lib/tomcats/pki/conf/sslserver.crt
$ chown tomcat.tomcat /var/lib/tomcats/pki/conf/sslserver.key
$ chmod 660 /var/lib/tomcats/pki/conf/sslserver.key
```

To configure SSL certificate:

```
$ pki-server http-connector-cert-add -i tomcat@pki \
    --certFile /var/lib/tomcats/pki/conf/sslserver.crt \
    --keyFile /var/lib/tomcats/pki/conf/sslserver.key
```

See also [PKI Server HTTP Connector Cert CLI](https://www.dogtagpki.org/wiki/PKI_Server_HTTP_Connector_Cert_CLI).

### Configuring SSL Certificate with JKS Keystore

To generate SSL certificate and key in JKS keystore:

```
$ keytool -genkey \
    -alias "sslserver" \
    -dname "CN=$HOSTNAME" \
    -keyalg RSA \
    -keystore /var/lib/tomcats/pki/conf/sslserver.jks \
    -storepass Secret.123 \
    -keypass Secret.123
$ chown tomcat.tomcat /var/lib/tomcats/pki/conf/sslserver.jks
$ chmod 660 /var/lib/tomcats/pki/conf/sslserver.jks
```

To configure SSL certificate:

```
$ pki-server http-connector-cert-add -i tomcat@pki \
    --keyAlias sslserver \
    --keystoreFile /var/lib/tomcats/pki/conf/sslserver.jks \
    --keystorePassword Secret.123
```

See also [PKI Server HTTP Connector Cert CLI](https://www.dogtagpki.org/wiki/PKI_Server_HTTP_Connector_Cert_CLI).

### Configuring SSL Certificate with PKCS \#12 Keystore

To generate SSL certificate and key in JKS keystore:

```
$ keytool -genkey \
    -alias "sslserver" \
    -dname "CN=$HOSTNAME" \
    -keyalg RSA \
    -storetype pkcs12 \
    -keystore /var/lib/tomcats/pki/conf/sslserver.p12 \
    -storepass Secret.123 \
    -keypass Secret.123
$ chown tomcat.tomcat /var/lib/tomcats/pki/conf/sslserver.p12
$ chmod 660 /var/lib/tomcats/pki/conf/sslserver.p12
```

To configure SSL certificate:

```
$ pki-server http-connector-cert-add -i tomcat@pki \
    --keyAlias sslserver \
    --keystoreType pkcs12 \
    --keystoreFile /var/lib/tomcats/pki/conf/sslserver.p12 \
    --keystorePassword Secret.123
```

See also [PKI Server HTTP Connector Cert CLI](https://www.dogtagpki.org/wiki/PKI_Server_HTTP_Connector_Cert_CLI).

### Configuring SSL Certificate with PKCS \#11 Keystore

To create NSS database:

```
$ pki-server nss-create -i tomcat@pki --password Secret.123
```

See also [NSS Database](https://www.dogtagpki.org/wiki/NSS_Database).

To create a self-signed SSL certificate:

```
$ echo "Secret.123" > password.txt
$ openssl rand -out noise.bin 2048
$ certutil -S \
 -x \
 -d /var/lib/tomcats/pki/alias \
 -f password.txt \
 -z noise.bin \
 -n sslserver \
 -s "CN=$HOSTNAME" \
 -t "CT,C,C" \
 -m $RANDOM \
 -k rsa \
 -g 2048 \
 -Z SHA256 \
 --keyUsage certSigning,keyEncipherment
```

See also [Creating Self-Signed SSL Server Certificate with NSS](https://www.dogtagpki.org/wiki/Creating_Self-Signed_SSL_Server_Certificate_with_NSS).

To enable JSS:

```
$ pki-server jss-enable -i tomcat@pki
```

This command will install JSS libraries and create the initial JSS configuration
in /var/lib/tomcats/pki/conf/jss.conf which can be customized as needed.

To configure SSL certificate:

```
$ pki-server http-connector-cert-add -i tomcat@pki \
    --keyAlias sslserver \
    --keystoreType pkcs11 \
    --keystoreProvider Mozilla-JSS
```

See also [PKI Server HTTP Connector Cert CLI](https://www.dogtagpki.org/wiki/PKI_Server_HTTP_Connector_Cert_CLI).

## Starting Tomcat Instance

To start Tomcat instance:

```
$ systemctl start tomcat@pki
```

To view Tomcat logs:

```
$ journalctl -u tomcat@pki
```

## Verifying SSL Configuration

To validate SSL configuration:

```
$ sslscan $HOSTNAME:8443
```

See also [sslscan](https://www.dogtagpki.org/wiki/Sslscan).

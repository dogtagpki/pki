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
$ pki-server http-connector-add -i tomcat@pki \
  --port 8443 \
  --scheme https \
  --secure true \
  --sslEnabled true \
  --sslProtocol SSL \
  Secure
```

This will create the Connector and SSLHost elements in /var/lib/tomcats/pki/conf/server.xml.

See also [PKI Server HTTP Connector CLI](https://www.dogtagpki.org/wiki/PKI_Server_HTTP_Connector_CLI).

## Configuring SSL Certificate

There are several ways to provide an SSL certificate to Tomcat:

 - with PKCS \#8 files
 - with JKS keystore
 - with PKCS \#12 keystore
 - with NSS database via PKCS \#11

The following procedure will generate the certificate and add a Certificate element in /var/lib/tomcats/pki/conf/server.xml.

### Configuring SSL Certificate with PKCS \#8 Files

To generate SSL certificate and key in PKCS \#8 files:

```
$ openssl req \
  -newkey rsa:2048 \
  -x509 \
  -nodes \
  -days 365 \
  -subj "/CN=$HOSTNAME" \
  -keyout /var/lib/tomcats/pki/conf/sslserver.key \
  -out /var/lib/tomcats/pki/conf/sslserver.crt
$ chown tomcat.tomcat /var/lib/tomcats/pki/conf/sslserver.crt
$ chmod 660 /var/lib/tomcats/pki/conf/sslserver.crt
$ chown tomcat.tomcat /var/lib/tomcats/pki/conf/sslserver.key
$ chmod 660 /var/lib/tomcats/pki/conf/sslserver.key
```

See also [Creating Self-Signed SSL Server Certificate with OpenSSL](https://www.dogtagpki.org/wiki/Creating_Self-Signed_SSL_Server_Certificate_with_OpenSSL).

To configure SSL certificate with PKCS \#8 files:

```
$ pki-server http-connector-cert-add -i tomcat@pki \
  --certFile /var/lib/tomcats/pki/conf/sslserver.crt \
  --keyFile /var/lib/tomcats/pki/conf/sslserver.key
```

See also [PKI Server HTTP Connector Cert CLI](https://www.dogtagpki.org/wiki/PKI_Server_HTTP_Connector_Cert_CLI).

### Configuring SSL Certificate with JKS Keystore

To generate SSL certificate and key in JKS keystore:

```
$ keytool -genkeypair \
  -keystore /var/lib/tomcats/pki/conf/keystore.jks \
  -storepass Secret.123 \
  -alias "sslserver" \
  -dname "CN=$HOSTNAME" \
  -keyalg RSA \
  -keypass Secret.123
$ chown tomcat.tomcat /var/lib/tomcats/pki/conf/keystore.jks
$ chmod 660 /var/lib/tomcats/pki/conf/keystore.jks
```

See also [Creating Self-Signed SSL Server Certificate with Keytool](https://www.dogtagpki.org/wiki/Creating_Self-Signed_SSL_Server_Certificate_with_Keytool).

To configure SSL certificate with JKS keystore:

```
$ pki-server http-connector-cert-add -i tomcat@pki \
  --keyAlias sslserver \
  --keystoreFile /var/lib/tomcats/pki/conf/keystore.jks \
  --keystorePassword Secret.123
```

See also [PKI Server HTTP Connector Cert CLI](https://www.dogtagpki.org/wiki/PKI_Server_HTTP_Connector_Cert_CLI).

### Configuring SSL Certificate with PKCS \#12 Keystore

To generate SSL certificate and key in PKCS \#12 keystore:

```
$ keytool -genkeypair \
  -keystore /var/lib/tomcats/pki/conf/keystore.p12 \
  -storetype pkcs12 \
  -storepass Secret.123 \
  -alias "sslserver" \
  -dname "CN=$HOSTNAME" \
  -keyalg RSA \
  -keypass Secret.123
$ chown tomcat.tomcat /var/lib/tomcats/pki/conf/keystore.p12
$ chmod 660 /var/lib/tomcats/pki/conf/keystore.p12
```

See also [Creating Self-Signed SSL Server Certificate with Keytool](https://www.dogtagpki.org/wiki/Creating_Self-Signed_SSL_Server_Certificate_with_Keytool).

To configure SSL certificate with PKCS \#12 keystore:

```
$ pki-server http-connector-cert-add -i tomcat@pki \
  --keyAlias sslserver \
  --keystoreType pkcs12 \
  --keystoreFile /var/lib/tomcats/pki/conf/keystore.p12 \
  --keystorePassword Secret.123
```

See also [PKI Server HTTP Connector Cert CLI](https://www.dogtagpki.org/wiki/PKI_Server_HTTP_Connector_Cert_CLI).

### Configuring SSL Certificate with NSS Database via PKCS \#11

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
  --keyUsage certSigning,keyEncipherment
```

See also [Creating Self-Signed SSL Server Certificate with NSS](https://www.dogtagpki.org/wiki/Creating_Self-Signed_SSL_Server_Certificate_with_NSS).

To enable JSS in Tomcat:

```
$ pki-server jss-enable -i tomcat@pki
```

This command will install JSS libraries and create the initial JSS configuration
in /var/lib/tomcats/pki/conf/jss.conf which can be customized as needed.

To configure SSL connector with JSS implementation:

```
$ pki-server http-connector-mod -i tomcat@pki \
  --sslImpl org.dogtagpki.tomcat.JSSImplementation \
  Secure
```

To configure SSL certificate with NSS database via PKCS \#11:

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

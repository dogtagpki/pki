# Installing Basic PKI Server

## Overview

This page describes the process to create and configure a basic PKI server without any of the PKI subsystems.
This would be useful to troubleshoot general server issues (e.g. SSL).

## Installation

```
$ dnf install pki-server
```

## Creating PKI Server

To create a PKI server:

```
$ pki-server create
```

This will create a PKI server in /var/lib/pki/pki-tomcat.

See also [PKI Server CLI](https://github.com/dogtagpki/pki/wiki/PKI-Server-CLI).

## Starting PKI Server

To start PKI server:

```
$ pki-server run
```

To stop the server, press Ctrl-C.

## Configuring SSL Connector

To create an SSL connector, execute the following command:

```
$ pki-server http-connector-add \
  --port 8443 \
  --scheme https \
  --secure true \
  --sslEnabled true \
  --sslProtocol SSL \
  Secure
```

This will create the Connector and SSLHost elements in /var/lib/pki/pki-tomcat/conf/server.xml.

See also [PKI Server HTTP Connector CLI](https://github.com/dogtagpki/pki/wiki/PKI-Server-HTTP-Connector-CLI).

## Configuring SSL Certificate

There are several ways to configure an SSL certificate:

 - with PKCS \#8 files
 - with JKS keystore
 - with PKCS \#12 keystore
 - with NSS database via PKCS \#11

The following procedure will generate the certificate and add a Certificate element in /var/lib/pki/pki-tomcat/conf/server.xml.

### Configuring SSL Certificate with PKCS \#8 Files

To generate SSL certificate and key in PKCS \#8 files:

```
$ openssl req \
  -newkey rsa:2048 \
  -x509 \
  -nodes \
  -days 365 \
  -subj "/CN=$HOSTNAME" \
  -keyout /var/lib/pki/pki-tomcat/conf/sslserver.key \
  -out /var/lib/pki/pki-tomcat/conf/sslserver.crt
$ chown pkiuser.pkiuser /var/lib/pki/pki-tomcat/conf/sslserver.crt
$ chmod 660 /var/lib/pki/pki-tomcat/conf/sslserver.crt
$ chown pkiuser.pkiuser /var/lib/pki/pki-tomcat/conf/sslserver.key
$ chmod 660 /var/lib/pki/pki-tomcat/conf/sslserver.key
```

See also [Creating Self-Signed SSL Server Certificate with OpenSSL](https://github.com/dogtagpki/pki/wiki/Creating-Self-Signed-SSL-Server-Certificate-with-OpenSSL).

To configure SSL certificate with PKCS \#8 files:

```
$ pki-server http-connector-cert-add \
  --certFile /var/lib/pki/pki-tomcat/conf/sslserver.crt \
  --keyFile /var/lib/pki/pki-tomcat/conf/sslserver.key
```

See also [PKI Server HTTP Connector Cert CLI](https://github.com/dogtagpki/pki/wiki/PKI-Server-HTTP-Connector-Cert-CLI).

### Configuring SSL Certificate with JKS Keystore

To generate SSL certificate and key in JKS keystore:

```
$ keytool -genkeypair \
  -keystore /var/lib/pki/pki-tomcat/conf/keystore.jks \
  -storepass Secret.123 \
  -alias "sslserver" \
  -dname "CN=$HOSTNAME" \
  -keyalg RSA \
  -keypass Secret.123
$ chown pkiuser.pkiuser /var/lib/pki/pki-tomcat/conf/keystore.jks
$ chmod 660 /var/lib/pki/pki-tomcat/conf/keystore.jks
```

See also [Creating Self-Signed SSL Server Certificate with Keytool](https://github.com/dogtagpki/pki/wiki/Creating-Self-Signed-SSL-Server-Certificate-with-Keytool).

To configure SSL certificate with JKS keystore:

```
$ pki-server http-connector-cert-add \
  --keyAlias sslserver \
  --keystoreFile /var/lib/pki/pki-tomcat/conf/keystore.jks \
  --keystorePassword Secret.123
```

See also [PKI Server HTTP Connector Cert CLI](https://github.com/dogtagpki/pki/wiki/PKI-Server-HTTP-Connector-Cert-CLI).

### Configuring SSL Certificate with PKCS \#12 Keystore

To generate SSL certificate and key in PKCS \#12 keystore:

```
$ keytool -genkeypair \
  -keystore /var/lib/pki/pki-tomcat/conf/keystore.p12 \
  -storetype pkcs12 \
  -storepass Secret.123 \
  -alias "sslserver" \
  -dname "CN=$HOSTNAME" \
  -keyalg RSA \
  -keypass Secret.123
$ chown pkiuser.pkiuser /var/lib/pki/pki-tomcat/conf/keystore.p12
$ chmod 660 /var/lib/pki/pki-tomcat/conf/keystore.p12
```

See also [Creating Self-Signed SSL Server Certificate with Keytool](https://github.com/dogtagpki/pki/wiki/Creating-Self-Signed-SSL-Server-Certificate-with-Keytool).

To configure SSL certificate with PKCS \#12 keystore:

```
$ pki-server http-connector-cert-add \
  --keyAlias sslserver \
  --keystoreType pkcs12 \
  --keystoreFile /var/lib/pki/pki-tomcat/conf/keystore.p12 \
  --keystorePassword Secret.123
```

See also [PKI Server HTTP Connector Cert CLI](https://github.com/dogtagpki/pki/wiki/PKI-Server-HTTP-Connector-Cert-CLI).

### Configuring SSL Certificate with NSS Database via PKCS \#11

First, create an NSS database:

```
$ pki-server nss-create --no-password
```

See also [NSS Database](https://github.com/dogtagpki/pki/wiki/NSS-Database).

Specify the SSL certificate extensions in a file (e.g. /var/lib/pki/pki-tomcat/conf/sslserver.conf):

```
basicConstraints       = critical, CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess    = OCSP;URI:http://ocsp.example.com
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth, clientAuth
```

Generate a SSL certificate request:

```
$ pki -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-request \
    --subject "CN=$HOSTNAME" \
    --ext /var/lib/pki/pki-tomcat/conf/sslserver.conf \
    --csr /var/lib/pki/pki-tomcat/conf/sslserver.csr
```

Create a self-signed SSL certificate:

```
$ pki -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-issue \
    --csr /var/lib/pki/pki-tomcat/conf/sslserver.csr \
    --ext /var/lib/pki/pki-tomcat/conf/sslserver.conf \
    --cert /var/lib/pki/pki-tomcat/conf/sslserver.crt
```

Import the certificate into the NSS database:

```
$ pki -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-import \
    --cert /var/lib/pki/pki-tomcat/conf/sslserver.crt \
    sslserver
```

See also [PKI NSS CLI](https://github.com/dogtagpki/pki/wiki/PKI-NSS-CLI).

Enable JSS with the following command:

```
$ pki-server jss-enable
```

This command will install JSS libraries and create the initial JSS configuration
in /var/lib/pki/pki-tomcat/conf/jss.conf which can be customized as needed.

Configure SSL connector with JSS implementation:

```
$ pki-server http-connector-mod \
  --sslImpl org.dogtagpki.tomcat.JSSImplementation \
  Secure
```

Finally, configure SSL certificate with NSS database via PKCS \#11:

```
$ pki-server http-connector-cert-add \
  --keyAlias sslserver \
  --keystoreType pkcs11 \
  --keystoreProvider Mozilla-JSS
```

See also [PKI Server HTTP Connector Cert CLI](https://github.com/dogtagpki/pki/wiki/PKI-Server-HTTP-Connector-Cert-CLI).

## Verifying SSL Configuration

To verify SSL configuration, restart the server and execute the following command:

```
$ sslscan $HOSTNAME:8443
```

See also [sslscan](https://www.dogtagpki.org/wiki/Sslscan).

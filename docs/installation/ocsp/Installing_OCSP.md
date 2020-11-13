Installing OCSP
===============

Overview
--------

This page describes the process to install an OCSP subsystem.

OCSP Subsystem Installation
---------------------------

Prepare a file (e.g. ocsp.cfg) that contains the deployment configuration.
A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ocsp.cfg](../../../base/server/examples/installation/ocsp.cfg).

Then execute the following command:

```
$ pkispawn -f ocsp.cfg -s OCSP
```

It will install OCSP subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ocsp/alias

**Note**: When OCSP is installed on a new system without any other subsystems,
it is necessary to provide the CA's root certificate. Specify the path to
the CA PKCS#7 PEM file in the `pki_cert_chain_path`. This will allow the server
to verify the CA's SSL server certificate when contacting the security domain.
It is up to the administrator to securely transport the CA root certificate
(public key only!) to the system prior to OCSP installation.

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
ocsp_signing                                                 u,u,u
subsystem                                                    u,u,u
ocsp_audit_signing                                           u,u,Pu
sslserver                                                    u,u,u
```

Verifying Admin Certificate
---------------------------

Prepare a client NSS database (e.g. ~/.dogtag/nssdb):

```
$ pki -c Secret.123 client-init
```

Import the CA signing certificate:

```
$ pki -c Secret.123 client-cert-import ca_signing --ca-cert ca_signing.crt
```

Import admin key and certificate:

```
$ pki -c Secret.123 client-cert-import \
 --pkcs12 ca_admin_cert.p12 \
 --pkcs12-password-file pkcs12_password.conf
```

Verify that the admin certificate can be used to access the OCSP subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin ocsp-user-show ocspadmin
----------------
User "ocspadmin"
----------------
  User ID: ocspadmin
  Full name: ocspadmin
  Email: ocspadmin@example.com
  Type: adminType
  State: 1
```

Verifying OCSP Client
---------------------

Publish the CRL in CA to the directory server as follows:

* Go to CA Agent UI (https://server.example.com:8443/ca/agent/ca/).
* Click **Update Directory Server**.
* Select **Update the certificate revocation list to the directory**.
* Click **Update Directory**.

Verify that the OCSPClient can be used to validate a certificate:

```
$ OCSPClient \
 -d /etc/pki/pki-tomcat/alias \
 -h server.example.com \
 -p 8080 \
 -t /ocsp/ee/ocsp \
 -c ca_signing \
 --serial 1
CertID.serialNumber=1
CertStatus=Good
```

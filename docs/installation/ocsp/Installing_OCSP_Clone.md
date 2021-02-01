Installing OCSP Clone
=====================

Overview
--------

This page describes the process to install a OCSP subsystem as a clone of an existing OCSP subsystem.

Before beginning with the installation, please ensure that you have configured the directory
server and added base entries.
The step is described [here](https://github.com/dogtagpki/pki/wiki/DS-Installation).

Additionally, make sure the FQDN has been [configured](../server/FQDN_Configuration.adoc) correctly.

Exporting Existing OCSP System Certificates
-------------------------------------------

On the existing system, export the existing OCSP system certificates with the following command:

```
$ pki-server ocsp-clone-prepare \
    --pkcs12-file ocsp-certs.p12 \
    --pkcs12-password Secret.123
```

The command will export the following certificates (including the certificate chain) and their keys into a PKCS #12 file:

* OCSP signing certificate
* audit signing certificate
* subsystem certificate

Note that the existing SSL server certificate will not be exported.

If necessary, third-party certificates (e.g. trust anchors) can be added into the same PKCS #12 file with the following command:

```
$ pki -d /etc/pki/pki-tomcat/alias -f /etc/pki/pki-tomcat/password.conf \
    pkcs12-cert-import <nickname> \
    --pkcs12-file ocsp-certs.p12 \
    --pkcs12-password Secret.123 \
    --append
```

OCSP Subsystem Installation
---------------------------

Prepare a deployment configuration (e.g. `ocsp-clone.cfg`) to deploy OCSP subsystem clone.
By default the subsystem will be deployed into a Tomcat instance called `pki-tomcat`.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ocsp-clone.cfg](../../../base/server/examples/installation/ocsp-clone.cfg).
It assumes that the primary CA and OCSP subsystems are running at https://primary.example.com:8443,
the CA signing certificate has been exported into `ca_signing.crt`,
the admin certificate and key have been exported into `ca_admin_cert.p12`,
and the password for this file has been exported into `pkcs12_password.conf`.
See [Installing CA](../ca/Installing_CA.md) for details.

To start the installation execute the following command:

```
$ pkispawn -f ocsp-clone.cfg -s OCSP
```

OCSP System Certificates
------------------------

After installation the existing OCSP system certificates (including the certificate chain)
and their keys will be stored in the server NSS database (i.e. `/etc/pki/pki-tomcat/alias`),
and a new SSL server certificate will be created for the new instance:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
ocsp_signing                                                 u,u,u
sslserver                                                    u,u,u
subsystem                                                    u,u,u
ocsp_audit_signing                                           u,u,Pu
```

If necessary, the certificates can be exported into PEM files with the following command:

```
$ pki-server cert-export <cert ID> --cert-file <filename>
```

The valid certificate IDs for OCSP are:
* `ocsp_signing`
* `ocsp_audit_signing`
* `subsystem`
* `sslserver`

Note that the `pki-server cert-export` command takes a certificate ID instead of a nickname.
For simplicity the nicknames in this example are configured to be the same as the certificate ID.

Admin Certificate
-----------------

To use the admin certificate from the CA subsystem, prepare a client NSS database (default is `~/.dogtag/nssdb`):

```
$ pki client-init
```

Then import the CA signing certificate into the client NSS database:

```
$ pki client-cert-import ca_signing --ca-cert ca_signing.crt
```

Finally, import admin certificate and key with the following command:

```
$ pki client-cert-import \
    --pkcs12 ca_admin_cert.p12 \
    --pkcs12-password-file pkcs12_password.conf
```

To verify that the admin certificate can be used to access the OCSP subsystem clone, execute the following command:

```
$ pki -n caadmin ocsp-user-show ocspadmin
----------------
User "ocspadmin"
----------------
  User ID: ocspadmin
  Full name: ocspadmin
  Email: ocspadmin@example.com
  Type: adminType
  State: 1
```

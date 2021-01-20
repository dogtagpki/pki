Installing TKS Clone
====================

Overview
--------

This page describes the process to install a TKS subsystem as a clone of an existing TKS subsystem.

Before beginning with the installation, please ensure that you have configured the directory
server and added base entries.
The step is described [here](https://github.com/dogtagpki/pki/wiki/DS-Installation).

Additionally, make sure the FQDN has been [configured](../server/FQDN_Configuration.adoc) correctly.

Exporting Existing TKS System Certificates
------------------------------------------

On the existing system, export the TKS system certificates with the following command:

```
$ pki-server tks-clone-prepare \
    --pkcs12-file tks-certs.p12 \
    --pkcs12-password Secret.123
```

The command will export the following certificates (including the certificate chain) and their keys into a PKCS #12 file:

* subsystem certificate
* audit signing certificate

Note that the existing SSL server certificate will not be exported.

If necessary, third-party certificates (e.g. trust anchors) can be added into the same PKCS #12 file with the following command:

```
$ pki -d /etc/pki/pki-tomcat/alias -f /etc/pki/pki-tomcat/password.conf \
    pkcs12-cert-import <nickname> \
    --pkcs12-file tks-certs.p12 \
    --pkcs12-password Secret.123 \
    --append
```

TKS Subsystem Installation
--------------------------

Prepare a deployment configuration (e.g. `tks-clone.cfg`) to deploy TKS subsystem clone.
By default the subsystem will be deployed into a Tomcat instance called `pki-tomcat`.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/tks-clone.cfg](../../../base/server/examples/installation/tks-clone.cfg).
It assumes that the primary CA and TKS are running at https://primary.example.com:8443,
the CA signing certificate has been exported into `ca_signing.crt`,
the admin certificate and key have been exported into `ca_admin_cert.p12`,
and the password for this file has been exported into `pkcs12_password.conf`.
See [Installing CA](../ca/Installing_CA.md) for details.

To start the installation execute the following command:

```
$ pkispawn -f tks-clone.cfg -s TKS
```

TKS System Certificates
-----------------------

After installation the existing TKS system certificates (including the certificate chain)
and their keys will be stored in the server NSS database (i.e. `/etc/pki/pki-tomcat/alias`),
and a new SSL server certificate will be created for the new instance:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
subsystem                                                    u,u,u
tks_audit_signing                                            u,u,Pu
sslserver                                                    u,u,u
```

If necessary, the certificates can be exported into PEM files with the following command:

```
$ pki-server cert-export <cert ID> --cert-file <filename>
```

The valid certificate IDs for TKS are:
* `tks_audit_signing`
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

To verify that the admin certificate can be used to access the TKS subsystem clone, execute the following command:

```
$ pki -n caadmin tks-user-show tksadmin
---------------
User "tksadmin"
---------------
  User ID: tksadmin
  Full name: tksadmin
  Email: tksadmin@example.com
  Type: adminType
  State: 1
```

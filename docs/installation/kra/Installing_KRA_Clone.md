Installing KRA Clone
====================

Overview
--------

This page describes the process to install a KRA subsystem as a clone of an existing KRA subsystem.

Before beginning with the installation, please ensure that you have configured the directory
server and added base entries.
The step is described [here](https://github.com/dogtagpki/pki/wiki/DS-Installation).

Additionally, make sure the FQDN has been [configured](../server/FQDN_Configuration.adoc) correctly.

Exporting Existing KRA System Certificates
------------------------------------------

On the existing system, export the KRA system certificates with the following command:

```
$ pki-server kra-clone-prepare \
    --pkcs12-file kra-certs.p12 \
    --pkcs12-password Secret.123
```

The command will export the following certificates (including the certificate chain) and their keys into a PKCS #12 file:

* KRA storage certificate
* KRA transport certificate
* audit signing certificate
* subsystem certificate

Note that the existing SSL server certificate will not be exported.

If necessary, third-party certificates (e.g. trust anchors) can be added into the same PKCS #12 file with the following command:

```
$ pki -d /var/lib/pki/pki-tomcat/conf/alias -f /var/lib/pki/pki-tomcat/conf/password.conf \
    pkcs12-cert-import <nickname> \
    --pkcs12-file kra-certs.p12 \
    --pkcs12-password Secret.123 \
    --append
```

KRA Subsystem Installation
--------------------------

Prepare a deployment configuration (e.g. `kra-clone.cfg`) to deploy KRA subsystem clone.
By default the subsystem will be deployed into a Tomcat instance called `pki-tomcat`.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/kra-clone.cfg](../../../base/server/examples/installation/kra-clone.cfg).
It assumes that the primary CA and KRA subsystems are running at https://primary.example.com:8443,
the CA signing certificate has been exported into `ca_signing.crt`,
and the admin certificate and key have been exported into `ca_admin_cert.p12`.
The PKCS #12 password is specified in the `pki_client_pkcs12_password` parameter.
See [Installing CA](../ca/Installing_CA.md) for details.

To start the installation execute the following command:

```
$ pkispawn -f kra-clone.cfg -s KRA
```

KRA System Certificates
-----------------------

After installation the existing KRA system certificates (including the certificate chain)
and their keys will be stored in the server NSS database (i.e. `/var/lib/pki/pki-tomcat/conf/alias`),
and a new SSL server certificate will be created for the new instance:

```
$ certutil -L -d /var/lib/pki/pki-tomcat/conf/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
kra_storage                                                  u,u,u
sslserver                                                    u,u,u
subsystem                                                    u,u,u
kra_audit_signing                                            u,u,Pu
kra_transport                                                u,u,u
```

If necessary, the certificates can be exported into PEM files with the following command:

```
$ pki-server cert-export <cert ID> --cert-file <filename>
```

The valid certificate IDs for KRA are:
* `kra_storage_signing`
* `kra_transport_signing`
* `kra_audit_signing`
* `subsystem`
* `sslserver`

Note that the `pki-server cert-export` command takes a certificate ID instead of a nickname.
For simplicity the nicknames in this example are configured to be the same as the certificate IDs.

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
$ pki pkcs12-import \
    --pkcs12 ca_admin_cert.p12 \
    --pkcs12-password Secret.123
```

To verify that the admin certificate can be used to access the KRA subsystem clone, execute the following command:

```
$ pki -n caadmin kra-user-show kraadmin
---------------
User "kraadmin"
---------------
  User ID: kraadmin
  Full name: kraadmin
  Email: kraadmin@example.com
  Type: adminType
  State: 1
```

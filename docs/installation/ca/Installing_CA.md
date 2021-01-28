Installing CA
=============

Overview
--------

This page describes the process to install a CA subsystem with a self-signed CA signing certificate.

Before beginning with the installation, please ensure that you have configured the directory
server and added base entries.
The step is described [here](https://github.com/dogtagpki/pki/wiki/DS-Installation).

Additionally, make sure the FQDN has been [configured](../server/FQDN_Configuration.adoc) correctly.

CA Subsystem Installation
-------------------------

Prepare a deployment configuration (e.g. `ca.cfg`) to deploy CA subsystem.
By default the subsystem will be deployed into a Tomcat instance called `pki-tomcat`.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ca.cfg](../../../base/server/examples/installation/ca.cfg).

To start the installation execute the following command:

```
$ pkispawn -f ca.cfg -s CA
```

CA System Certificates
----------------------

After installation the CA system certificates and keys will be stored
in the server NSS database (i.e. `/etc/pki/pki-tomcat/alias`):

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CTu,Cu,Cu
ca_ocsp_signing                                              u,u,u
subsystem                                                    u,u,u
ca_audit_signing                                             u,u,Pu
sslserver                                                    u,u,u
```

If necessary, the certificates can be exported into PEM files with the following command:

```
$ pki-server cert-export <cert ID> --cert-file <filename>
```

The valid certificate IDs for CA are:
* `ca_signing`
* `ca_ocsp_signing`
* `ca_audit_signing`
* `subsystem`
* `sslserver`

Note that the `pki-server cert-export` command takes a certificate ID instead of a nickname.
For simplicity the nicknames in this example are configured to be the same as the certificate ID.

Admin Certificate
-----------------

After installation the admin certificate and key will be stored
in `~/.dogtag/pki-tomcat/ca_admin_cert.p12`.
The password for this file will be stored in `~/.dogtag/pki-tomcat/ca/pkcs12_password.conf`.

To use the admin certificate, prepare a client NSS database (default is `~/.dogtag/nssdb`):

```
$ pki client-init
```

Export the CA signing certificate from the server NSS database:

```
$ pki-server cert-export ca_signing --cert-file ca_signing.crt
```

Then import the CA signing certificate into the client NSS database:

```
$ pki client-cert-import ca_signing --ca-cert ca_signing.crt
```

Finally, import admin certificate and key with the following command:

```
$ pki client-cert-import \
   --pkcs12 ~/.dogtag/pki-tomcat/ca_admin_cert.p12 \
   --pkcs12-password-file ~/.dogtag/pki-tomcat/ca/pkcs12_password.conf
```

To verify that the admin certificate can be used to access the CA subsystem, execute the following command:

```
$ pki -n caadmin ca-user-show caadmin
--------------
User "caadmin"
--------------
  User ID: caadmin
  Full name: caadmin
  Email: caadmin@example.com
  Type: adminType
  State: 1
```

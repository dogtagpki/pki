Installing KRA Clone
====================

Overview
--------

This page describes the process to install a KRA subsystem as a clone of an existing KRA subsystem.

Exporting Existing System Certificates
--------------------------------------

Export the existing system certificates (including the certificate chain) into a PKCS #12 file, for example:

```
$ pki-server kra-clone-prepare --pkcs12-file kra-certs.p12 --pkcs12-password Secret.123
```

If necessary, third-party certificates (e.g. trust anchors) can be added into the same PKCS #12 file with the following command:

```
$ pki -d /etc/pki/pki-tomcat/alias -f /etc/pki/pki-tomcat/password.conf \
    pkcs12-cert-import <nickname> --pkcs12-file kra-certs.p12 --pkcs12-password Secret.123 --append
```

KRA Subsystem Installation
--------------------------

Prepare a file (e.g. kra-clone.cfg) that contains the deployment configuration.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/kra-clone.cfg](../../../base/server/examples/installation/kra-clone.cfg).
It assumes that the primary CA and KRA are running at https://primary.example.com:8443,
the CA signing certificate has been exported into `ca_signing.crt`,
the admin certificate and key have been exported into `ca_admin_cert.p12`,
and the admin PKCS #12 password file has been exported into `pkcs12_password.conf`.

Then execute the following command:

```
$ pkispawn -f kra-clone.cfg -s KRA
```

It will install KRA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/kra/alias

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
kra_storage                                                  u,u,u
sslserver                                                    u,u,u
subsystem                                                    u,u,u
kra_audit_signing                                            u,u,Pu
kra_transport                                                u,u,u
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

Import the admin key and certificate:

```
$ pki -c Secret.123 client-cert-import \
 --pkcs12 ca_admin_cert.p12 \
 --pkcs12-password-file pkcs12_password.conf
```

Verify that the admin certificate can be used to access the KRA clone by executing the following command:

```
$ pki -c Secret.123 -n caadmin kra-user-show kraadmin
---------------
User "kraadmin"
---------------
  User ID: kraadmin
  Full name: kraadmin
  Email: kraadmin@example.com
  Type: adminType
  State: 1
```

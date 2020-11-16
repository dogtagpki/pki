Installing Subordinate CA
=========================

Overview
--------

This page describes the process to install a subordinate CA subsystem
with a signing certificate issued by a root CA.


Before beginning with the installation, please ensure that you have configured the directory
server and added base entries.
The step is described [here](https://github.com/dogtagpki/pki/wiki/DS-Installation).

Additionally, make sure the FQDN has been [configured](../server/FQDN_Configuration.adoc) correctly.

Subordinate CA Subsystem Installation
-------------------------------------

Prepare a file (e.g. subca.cfg) that contains the deployment configuration.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/subca.cfg](../../../base/server/examples/installation/subca.cfg).
It assumes that the root CA is already running at https://root.example.com:8443
and the root CA signing certificate has been exported into `root-ca_signing.crt`.

Then execute the following command:

```
$ pkispawn -f subca.cfg -s CA
```

It will install subordinate CA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ca/alias

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

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

Verifying Admin Certificate
---------------------------

Prepare a client NSS database (e.g. ~/.dogtag/nssdb):

```
$ pki client-init
```

Import the root CA signing certificate:

```
$ pki client-cert-import ca_signing --ca-cert root-ca_signing.crt
```

Import admin key and certificate:

```
$ pki client-cert-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password-file /root/.dogtag/pki-tomcat/ca/pkcs12_password.conf
```

Verify that the admin certificate can be used to access the subordinate CA subsystem by executing the following command:

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

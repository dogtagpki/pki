Installing CA Clone
===================

Overview
--------

This page describes the process to install a CA subsystem as a clone of an existing CA subsystem.

Before beginning with the installation, please ensure that you have configured the directory
server and added base entries. This step is described [here](http://www.dogtagpki.org/wiki/Installing_DS).

Additionally, please verify that your FQDN is correctly reported by the following command:

    python -c 'import socket; print(socket.getfqdn())'

If it isn't, please add an entry at the beginning of the `/etc/hosts` file:

    127.0.0.1 clone.example.com
    ::1 clone.example.com

Some useful tips:

 - Make sure the firewall on the master allows external access to LDAP from the clone
 - Make sure the firewall on the clone allows external access to LDAP from the master
 - Not having a `dc=pki,dc=example,dc=com` entry in LDAP will give the same error as
       not being able to connect to the LDAP server.

Exporting Existing System Certificates
--------------------------------------

Export the existing system certificates (including the certificate chain) into a PKCS #12 file, for example:

```
$ pki-server ca-clone-prepare --pkcs12-file ca-certs.p12 --pkcs12-password Secret.123
```

If necessary, third-party certificates (e.g. trust anchors) can be added into the same PKCS #12 file with the following command:

```
$ pki -d /etc/pki/pki-tomcat/alias -f /etc/pki/pki-tomcat/password.conf \
    pkcs12-cert-import <nickname> --pkcs12-file ca-certs.p12 --pkcs12-password Secret.123 --append
```

Set SELinux permissions
-----------------------
After copying the ca-certs.p12 to the clone machine, ensure that appropriate SELinux rules are added:

````
semanage fcontext -a -t pki_tomcat_cert_t ca-certs.p12
restorecon -R -v ca-certs.p12
````

CA Subsystem Installation
-------------------------

Prepare a file (e.g. ca.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

[CA]
pki_admin_email=caadmin@example.com
pki_admin_name=caadmin
pki_admin_nickname=caadmin
pki_admin_password=Secret.123
pki_admin_uid=caadmin

pki_client_database_password=Secret.123
pki_client_database_purge=False
pki_client_pkcs12_password=Secret.123

pki_ds_base_dn=dc=ca,dc=pki,dc=example,dc=com
pki_ds_database=ca
pki_ds_password=Secret.123

pki_security_domain_hostname=server.example.com
pki_security_domain_https_port=8443
pki_security_domain_user=caadmin
pki_security_domain_password=Secret.123

pki_ca_signing_nickname=ca_signing
pki_ocsp_signing_nickname=ca_ocsp_signing
pki_audit_signing_nickname=ca_audit_signing
pki_sslserver_nickname=sslserver
pki_subsystem_nickname=subsystem

pki_clone=True
pki_clone_replicate_schema=True
pki_clone_uri=https://server.example.com:8443
pki_clone_pkcs12_path=ca-certs.p12
pki_clone_pkcs12_password=Secret.123
```

In the above, replace `server.example.com` with the hostname of the
master instance. Note that an alternate replica can be specified for
the value of `pki_clone_uri`.

Then execute the following command:

```
$ pkispawn -f ca.cfg -s CA
```

It will install CA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
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
$ pki -c Secret.123 client-init
```

Import the CA signing certificate:

```
$ pki -c Secret.123 client-cert-import ca_signing --ca-cert ca_signing.crt
```

Import the master's admin key and certificate:

```
$ pki -c Secret.123 client-cert-import \
 --pkcs12 ca_admin_cert.p12 \
 --pkcs12-password-file pkcs12_password.conf
```

Verify that the admin certificate can be used to access the CA clone by executing the following command:

```
$ pki -c Secret.123 -n caadmin ca-user-show caadmin
--------------
User "caadmin"
--------------
  User ID: caadmin
  Full name: caadmin
  Email: caadmin@example.com
  Type: adminType
  State: 1
```

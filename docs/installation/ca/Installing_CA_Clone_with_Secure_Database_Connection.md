Installing CA Clone with Secure Database Connection
===================================================

Overview
--------

This page describes the process to install a CA subsystem as clone of an existing CA subsystem with a secure database connection.

DS Installation
---------------

Before beginning with the installation, please ensure that you have configured the directory
server as described in [DS Installation](https://github.com/dogtagpki/pki/wiki/DS-Installation).

Then on existing system, export the DS signing certificate into `ds_signing.p12` and copy the certificate into clone system with the following command:

```
pki -d /etc/dirsrv/slapd-localhost \
-C /etc/dirsrv/slapd-localhost/pwdfile.txt \
pkcs12-export --pkcs12-file ds_signing.p12 \
--pkcs12-password Secret.123 Self-Signed-CA
```
Import the `ds_signing.p12` into the clone DS instance with the following command:

```
pki -d /etc/dirsrv/slapd-localhost \
-C /etc/dirsrv/slapd-localhost/pwdfile.txt \
pkcs12-import --pkcs12-file ds_signing.p12 \
--pkcs12-password Secret.123
```
On clone system, Create DS Server Certificate as described in [Creating DS Server Certificate](https://github.com/dogtagpki/pki/wiki/Enabling-SSL-Connection-in-DS#creating-ds-server-certificate).
Note that the Subject DN i.e `--subject "CN=hostname"` should be the same as of the clone system's name.

Then enable the SSL connection as described in [Enabling SSL Connection](https://github.com/dogtagpki/pki/wiki/Enabling-SSL-Connection-in-DS#enabling-ssl-connection).

After the successful DS restart, Export the DS Signing Certificate into 'ds_signing.crt' as described in [Exporting DS Signing Certificate](https://github.com/dogtagpki/pki/wiki/Exporting-DS-Certificates#exporting-ds-signing-certificate).

Some useful tips:

 - Make sure the firewall on the master allows external access to LDAP from the clone
 - Make sure the firewall on the clone allows external access to LDAP from the master
 - Not having a `dc=pki,dc=example,dc=com` entry in LDAP will give the same error as
       not being able to connect to the LDAP server.


Exporting Existing CA System Certificates
-----------------------------------------

On the existing system, export the CA system certificates and copy to clone system with the following command:

```
pki-server ca-clone-prepare --pkcs12-file ca-certs.p12 --pkcs12-password Secret.123
pki-server cert-export ca_signing --cert-file ca_signing.crt
```

The command will export the following certificates (including the certificate chain) and their keys into a PKCS #12 file:

* CA signing certificate
* OCSP signing certificate
* audit signing certificate
* subsystem certificate

Note that the existing SSL server certificate will not be exported.

If necessary, third-party certificates (e.g. trust anchors) can be added into the same PKCS #12 file with the following command:

```
$ pki -d /etc/pki/pki-tomcat/alias -f /etc/pki/pki-tomcat/password.conf \
    pkcs12-cert-import <nickname> \
    --pkcs12-file ca-certs.p12 \
    --pkcs12-password Secret.123 \
    --append
```

SELinux Permissions
-------------------

After copying the `ca-certs.p12` to the clone machine, ensure that appropriate SELinux rules are added:

````
$ semanage fcontext -a -t pki_tomcat_cert_t ca-certs.p12
$ restorecon -R -v ca-certs.p12
````

Also, make sure the `ca-certs.p12` file is owned by the `pkiuser`

````
$ chown pkiuser:pkiuser ca-certs.p12
````

CA Subsystem Installation
-------------------------

Prepare a deployment configuration (e.g. `ca-secure-ds-secondary.cfg`) to deploy CA subsystem clone.
By default the subsystem will be deployed into a Tomcat instance called `pki-tomcat`.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ca-secure-ds-secondary.cfg](../../../base/server/examples/installation/ca-secure-ds-secondary.cfg).
It assumes that the primary CA subsystem is running at https://primary.example.com:8443,
the CA signing certificate has been exported into `ca_signing.crt`,
the admin certificate and key have been exported into `ca_admin_cert.p12`,
and the password for this file has been exported into `pkcs12_password.conf`.

To start the installation execute the following command:

```
$ pkispawn -f ca-secure-ds-secondary.cfg -s CA
```

CA System Certificates
----------------------

After installation the existing CA system certificates (including the certificate chain)
and their keys will be stored in the server NSS database (i.e. `/etc/pki/pki-tomcat/alias`),
and a new SSL server certificate will be created for the new instance:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

subsystem                                                    u,u,u
ca_signing                                                   CTu,Cu,Cu
ca_ocsp_signing                                              u,u,u
ca_audit_signing                                             u,u,Pu
ds_signing                                                   CT,C,C
sslserver                                                    u,u,u
```

If necessary, the clone CA system certificates can be exported into PEM files with the following command:

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
For simplicity the nicknames in this example are configured to be the same as the certificate IDs.

Admin Certificate
-----------------

To use the admin certificate from the primary CA subsystem, prepare a client NSS database (default is `~/.dogtag/nssdb`):

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

To verify that the admin certificate can be used to access the CA subsystem clone, execute the following command:

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

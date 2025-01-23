Offline System Certificate Renewal
==================================

## Overview

PKI server provides a mechanism to recover from expired system certificates.
This mechanism can also be used to renew the certificates before they expire.

There are 2 ways to renew the certificates:

* [Automated Renewal Process](#Automated-Renewal-Process) - supports LDAPS/LDAPI configuration
* [Manual Renewal Process](#Manual-Renewal-Process) - supports LDAP/LDAPS/LDAPI configuration

**NOTE:** For IPA follow [this page](https://github.com/dogtagpki/freeipa/wiki/Renewing-System-Certificates) instead.

## Automated Renewal Process

**NOTE:** If you have a **non-secure** LDAP setup and if you **don't know the agent username/password**, use the manual process instead.

### Prerequisite

* Valid CA certificate
* TLS configured Directory Server
* If Dogtag was configured to use TLS certificate authentication to bind to LDAP, a valid DS service certificate
* `pki-server cert-fix` must be run as `root`
* The password of the specified agent account will be reset. If needed, it can be changed back afterwards (manually; successful execution of `pki-server cert-fix` proves that the operator has privileges to do this)
* The password of the `pkidbuser` account will be reset

### Usage

One line tool that fixes all certificates:

```
$ pki-server cert-fix \
    --ldap-url <LDAP URL> \
    --agent-uid <agent UID>
```

For all available options, you can type:

```
$ pki-server cert-fix --help
```

## Manual Renewal Process

### Initialization

It is recommended to run the following steps to ensure that `CS.cfg` and NSS database are synchronized and that the server can operate without any issues.

Disable self tests using the following command:

```
$ pki-server selftest-disable
```

Synchronize NSS database and `CS.cfg` for all system certificates that are to be renewed.

```
$ pki-server cert-update <cert ID>
```

Stop PKI server.

```
$ pki-server stop
```

### Configuring DS Connection

**NOTE 1:** If you have a **valid admin cert** OR if you know the **agent username/password**, you can skip this section.

**NOTE 2:** Note down the values that you change in the following steps as it needs to be restored at the end of the process

There are 2 different scenarios based on value of `internaldb.ldapauth.authtype` in your target subsystems' `CS.cfg`:

If the DS certificate has expired, update the following parameters in `CS.cfg`:

```
internaldb.ldapconn.port=389
internaldb.ldapconn.secureConn=false
```

If the DS certificate is still valid, set the agent password with the following command:

```
$ ldappasswd \
    -H <LDAP host URL> \
    -D 'cn=Directory Manager' \
    -y <LDAP password> \
    -s <agent password> \
    uid=<agent UID>,ou=people,<internaldb.basedn>
```

**NOTE:** If your `<LDAP host URL>` starts with `ldap://`, add `-ZZ` flag to the above command.

Set the LDAP password in `password.conf`:

```
$ echo internaldb=<LDAP password> >> /var/lib/pki/<instance>/conf/password.conf
```

### Creating Temporary SSL Server Certificate

Create a temporary SSL server certificate.
The certificate will be created in `/var/lib/pki/<instance>/conf/certs/sslserver.crt`.

```
$ pki-server cert-create sslserver --temp
```

Delete the existing system certificate if exists.

```
$ pki-server cert-del sslserver
```

Import the certificate created in previous step.

```
$ pki-server cert-import sslserver
```

Start PKI server.

```
$ pki-server start
```

### Renewing System Certificates

Use a **valid admin cert** OR **agent's username/password** to renew required system certs using PKI tool.
For **`sslserver`** cert provide the `serial number` from the **original SSL server cert** to avoid placing request for unintended cert.

```
$ pki-server cert-create \
    --renew \
    -n <admin cert nickname> \
    -d <admin NSS database> \
    -c <admin NSS database password> \
    <cert ID> \
    --serial <serial number>
```

**OR**

```
$ pki-server cert-create \
    --renew \
    -u <agent username> \
    -w <agent password> \
    <cert ID> \
    --serial <serial number>
```

**OR**

using 3rd party tool, like certmonger. Please refer [certmonger manual](https://www.freeipa.org/page/Certmonger) to renew the certs.

### Updating System Certificates

Stop PKI server before installing the new certificates.

```
$ pki-server stop
```

Delete the existing certificates from NSS database.

```
$ pki-server cert-del <cert ID>
```

Import the renewed permanent certificates into NSS database and update corresponding `CS.cfg` files.

```
$ pki-server cert-import <cert ID>
```

**Note:** Make sure the audit signing certificates have `u,u,Pu` trust flags by running the following command:

```
$ certutil -L -d /var/lib/pki/<instance>/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI
ca_signing                                                   CTu,Cu,Cu
transportCert cert-pki-tomcat KRA                            u,u,u
storageCert cert-pki-tomcat KRA                              u,u,u
auditSigningCert cert-pki-tomcat KRA                         u,u,Pu
subsystem                                                    u,u,u
sslserver                                                    u,u,u
ca_ocsp_signing                                              u,u,u
ca_audit_signing                                             u,u,Pu
```

Enable the self test using the following command:

```
$ pki-server selftest-enable
```

Restore the `CS.cfg` values that you modified earlier in [Configuring DS Connection](#Configuring-DS-Connection) section.

Start PKI server with the new system certificates.

```
$ pki-server start
```

Offline System Certificate Renewal
==================================

## Overview

PKI server provides a mechanism to recover from expired system certificates. This mechanism can also be
used to renew the certificates before they expire. There are 2 ways to renew the certs

1. [Automated Renewal Process](#Automated-Renewal-Process) - supports LDAPS/LDAPI configuration
2. [Manual Renewal Process](#Manual-Renewal-Process) - supports LDAP/LDAPS/LDAPI configuration

**NOTE:** For IPA follow [this page](https://github.com/dogtagpki/freeipa/wiki/Renewing-System-Certificates) instead.

## Automated Renewal Process

**NOTE:** If you have a **non-secure** LDAP setup and if you **don't know the agent username/password**, use the manual process instead.

### Prerequisite

- Valid CA certificate
- TLS configured Directory Server
- If Dogtag was configured to use TLS certificate authentication to bind to LDAP, a valid DS service certificate
- `pki-server cert-fix` must be run as `root`
- The password of the specified agent account will be reset. If needed, it can be changed back afterwards (manually; successful execution of `pki-server cert-fix` proves that the operator has privileges to do this)
- The password of the `pkidbuser` account will be reset

### Usage

One line tool that fixes all certificates:

    # pki-server cert-fix \
        --ldap-url <LDAP URL> \
        --agent-uid <agent UID>

For all available options, you can type:

    $ pki-server cert-fix --help

## Manual Renewal Process

### Initialization

It is recommended to run the following steps to ensure that `CS.cfg` and NSS database are synchronized and that the server can operate without any issues.

1. Disable self tests using the following command:
    ````
    # pki-server selftest-disable
    ````

2. Synchronize NSS database and CS.cfg for all system certificates that are to be renewed
    ````
    # pki-server cert-update <cert ID>
    ````

3. Stop pki-tomcat instance
    ````
    # systemctl stop pki-tomcatd@<instance>
    ````

### Configuring LDAP

**NOTE 1:** If you have a **valid admin cert** OR if you know the **agent username/password**, you can skip this section.

**NOTE 2:** Note down the values that you change in the following steps as it needs to be restored at the end of the process

There are 2 different scenarios based on value of `internaldb.ldapauth.authtype` in your target subsystems' CS.cfg:

1. Update corresponding CS.cfg key-values as follows:

    ````
    internaldb.ldapconn.port=389
    internaldb.ldapconn.secureConn=false
    ````

2. Set the agent password (requires a secure connection to LDAP)
    ````
    # ldappasswd -H <LDAP host URL> -D 'cn=Directory Manager' -y <LDAP password> -s <agent password> uid=<agent UID>,ou=people,<internaldb.basedn>
    ````
    **NOTE:** If your `<LDAP host URL>` starts with `ldap://`, add `-ZZ` flag to the above command

3. Set the LDAP password in `password.conf`:
    ````
    # echo internaldb=<LDAP password> >> /var/lib/pki/pki-tomcat/conf/password.conf
    ````

### Bringing up the PKI server

1. Create temp SSL certificate. The temp cert will be created in `/var/lib/pki/<instance>/conf/certs/sslserver.crt`
    ````
    # pki-server cert-create sslserver --temp
    ````

2. Delete the existing System cert if exist
    ````
    # pki-server cert-del sslserver
    ````

3. Import temp SSL certificate created in previous step
    ````
    # pki-server cert-import sslserver
    ````

4. Start server
    ````
    # systemctl start pki-tomcatd@<instance>
    ````

### System Certificate Renewal

1. Use a **valid admin cert** OR **agent's username/password** to renew required system certs using PKI tool. For **`sslserver`** cert provide the `serial number` from the **original SSL server cert** to avoid placing request for unintended cert.
    ````
    # pki-server cert-create --renew \
        -n <admin cert nickname> \
        -d <admin NSS database> \
        -c <admin NSS database password> \
        <cert ID> \
        --serial <serial number>
    ````

    **OR**

    ````
    # pki-server cert-create --renew \
        -u <agent username> \
        -w <agent password> \
        <cert ID> \
        --serial <serial number>
    ````

    **OR**

    using 3rd party tool, like certmonger. Please refer [certmonger manual](https://www.freeipa.org/page/Certmonger) to renew the certs.

2. Stop server to update PKI server instance to use latest renewed certs
    ````
    # systemctl stop pki-tomcatd@pki-tomcat
    ````

3. Delete the existing NSS database certs
    ````
    # pki-server cert-del <cert ID>
    ````

4. Import the renewed permanent certs into NSS db and update corresponding CS.cfg files
    ````
    # pki-server cert-import <cert ID>
    ````

    **Note:** Make sure the audit signing certificates have `u,u,Pu` trust flags by running the following command:
    ````
    # certutil -L -d /var/lib/pki/pki-tomcat/alias/

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
    ````
5. Enable the self test using the following command:
    ````
    # pki-server selftest-enable
    ````
6. Restore the `CS.cfg` values that you modified earlier in [Configuring LDAP](#Configuring-LDAP) section

7. Start server with new renewed system certificates.
    ````
    # systemctl start pki-tomcatd@pki-tomcat
    ````
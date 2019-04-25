Offline System Certificate Renewal
==================================

## Overview

PKI server provides a mechanism to recover from expired system certificates. This mechanism can also be
used to renew the certificates before they expire. There are 2 ways to renew the certs

1. [Automated Renewal Process](#Automated-Renewal-Process) - supports LDAPS/LDAPI configuration
2. [Manual Renewal Process](#Manual-Renewal-Process) - supports LDAP/LDAPS/LDAPI configuration

This tool's behavior is different in an **IPA environment** and **standalone PKI environment**

## Automated Renewal Process

### IPA Environment (Uses LDAPI)

#### Assumptions:

- Valid CA certificate
- `cert-fix` must be run as `root`
- `LDAPI` must be configured, with `root` autobinding to `cn=Directory Manager` or other account with privileges on `o=ipaca` subtree, including password reset privileges
- The password of the specified agent account will be reset. If needed, it can be changed back afterwards (manually; successful execution of `cert-fix` proves that the operator has privileges to do this)
- The password of the `pkidbuser` account will be reset
- LDAPI (ldappasswd) and need to be root

#### Usage:

One line tool that fixes **all** certificates:

    # pki-server cert-fix \
    --agent-uid <agent UID> \
    --ldapi-socket /var/run/slapd-REALM.socket

If you need to fix only a **specific system certificates**, use the `--cert <Cert_ID>` option. If you need to renew **non-system certs**, use the `--extra-cert <Serial>` option.


### Standalone PKI environment (Uses LDAPS)

#### Assumptions:

- Valid CA certificate
- TLS configured Directory Server
- If Dogtag was configured to use TLS certificate authentication to bind to LDAP, a Valid DS service certificate

#### Usage:

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

### Bringing up the PKI server

1. Create temp SSL certificate. The temp cert will be created in `/etc/pki/<instance>/certs/sslserver.crt`
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
    # systemctl start pki-tomcatd@pki-tomcat
    ````

### Configuring LDAP

Based on the LDAP configuration, you might need to perform these additional steps. If you have a **valid admin cert** OR if you have **non secure** LDAP setup, you can skip this section.

There are 2 different scenarios based on value of `internaldb.ldapauth.authtype` in your target subsystems' CS.cfg:

#### IPA Environment (Uses LDAPI)
1. Update corresponding CS.cfg key-values as follows:

    ````
    internaldb.ldapauth.authtype=BasicAuth
    internaldb.ldapconn.port=389
    internaldb.ldapconn.secureConn=false
    internaldb.ldapauth.bindDN=uid=pkidbuser,ou=people,<internaldb.basedn>
    ````

2. Set a LDAP password using `ldappasswd`:
    ````
    # ldappasswd -H /var/run/slapd-REALM.socket -Y EXTERNAL -s <new pasword> uid=pkidbuser,ou=people,<internaldb.basedn>
    ````

#### PKI Standalone Environment (Uses LDAPS)

1. Update corresponding CS.cfg key-values as follows:

    ````
    internaldb.ldapconn.port=389
    internaldb.ldapconn.secureConn=false
    ````

### System Certificate Renewal

1. This step requires a  **valid admin cert** to renew required system certs using PKI tool. For **`sslserver`** cert provide the `serial number` from the **original SSL server cert** to avoid placing request for unintended cert.
    ````
    # pki-server cert-create --renew \
    -n <admin cert nickname> \
    -d <admin NSS database> \
    -c <admin NSS database password> \
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

    *Note:* Make sure the **Audit Log** has the trust flags: ***"u,u,Pu"*** by running the following command:
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

6. Start server with new renewed system certificates.
    ````
    # systemctl start pki-tomcatd@pki-tomcat
    ````
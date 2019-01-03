Offline System Certificate Renewal
==================================

## Overview

PKI server provides a mechanism to recover from expired system certificates. This mechanism can also be
used to renew the certificates before they expire. There are 2 ways to renew the certs

1. [Automated Renewal Process](#Automated-Renewal-Process)
2. [Manual Renewal Process](#Manual-Renewal-Process) 

It is assumed that you have the following:
* Valid CA signing cert
* Valid admin cert

To verify these assumptions are valid:

1. List details of all system certificates. (Note down the `<cert ID>` of the certificates that need to be renewed)

    ````
    # pki-server cert-find

      Cert ID: ca_signing
      Nickname: ca_signing
      Serial Number: 0x1
      Subject DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
      Issuer DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
      Not Valid Before: Wed Dec 19 17:33:21 2018
      Not Valid After: Sun Dec 19 17:33:21 2038
    ````

2. Check details of the admin certificate

    ````
    # certutil -L \
    -d <admin NSS database> \
    -n <admin cert nickname>

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 6 (0x6)
            Signature Algorithm: PKCS #1 SHA-256 With RSA Encryption
            Issuer: "CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE"
            Validity:
                Not Before: Sat Dec 15 02:16:26 2018
                Not After : Fri Dec 04 02:16:26 2020
            Subject: "CN=PKI Administrator,E=caadmin@example.com,OU=pki-tomcat,O=
                EXAMPLE"

    ````

## Automated Renewal Process

One line tool that fixes all certificates:

    # pki-server cert-fix \
    -n <admin cert nickname> \
    -d <admin NSS database> \
    -c <admin NSS database password>

One line tool to fix one particular certificate:

    # pki-server cert-fix --cert <cert ID> \
    -n <admin cert nickname> \
    -d <admin NSS database> \
    -c <admin NSS database password>

For all available options, you can type:

    $ pki-server cert-fix --help

## Manual Renewal Process
### Initialization

It is recommended to run the following steps to ensure that `CS.cfg` and NSS database are synchronized and that the server can operate without any issues.

1. Disable self tests using the built-in tool:
    ````
    # pki-server selftest-disable -i <instance_name>
    ````

2. Synchronize NSS database and CS.cfg for all system certificates that are to be renewed
    ````
    # pki-server cert-update <cert ID>
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

### System Certificate Renewal

1. Renew required system certs using PKI tool. For **`sslserver`** cert provide the `serial number` from the **original SSL server cert** to avoid placing request for unintended cert.
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

3. Delete the existing NSS db certs
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
5. Enable the self test using the built-in tool available:
    ````
    # pki-server selftest-enable
    ````

6. Start server with new renewed system certificates.
    ````
    # systemctl start pki-tomcatd@pki-tomcat
    ````
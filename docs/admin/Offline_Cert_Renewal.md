Offline Cert Renewal
====================

## Overview

PKI server provides a mechanism to recover from expired system certificates. This mechanism can also be
used to renew the certificates before they expire. There are 2 ways to renew the certs

1. [Automated Renewal Process](#Automated-Renewal-Process)
2. [Manual Renewal Process](#Manual-Renewal-Process) 

It is assumed that you have the following:
* Valid CA signing cert
* Valid admin cert

To verify these assumptions are valid:

1. List details of all system certificates. (Note down the `<cert ID>` of the certs that needs to be renewed)

    ````
    # pki-server cert-find
    ````

2. Check details of admin cert

    ````
    # certutil -L \
    -d <client NSS DB dir> \
    -n <admin cert nickname>
    ````

3. Check status of PKI server

    ````
    # systemctl status pki-tomcatd@pki-tomcat
    ````

## Automated Renewal Process

One line tool that fixes all certificates:

    # pki-server cert-fix \
    -n <admin nickname> \
    -d <NSS db path> \
    -c <NSS client DB password>


One line tool to fix one particular certificate:

    # pki-server cert-fix --cert <cert ID> \
    -n <admin nickname> \
    -d <NSS db path> \
    -c <NSS client DB password>

For all available options, you can type:

    $ pki-server cert-fix --help

## Manual Renewal Process
### Initialization

It is recommended to run the following steps to ensure that `CS.cfg` and NSS db are synchronized and
that the server can operate without any issues.

1. Disable self tests. Remove the following line from CS.cfg for the <subsystem> you are renewing.
The CS.cfg is located in `/etc/pki/<instance>/<subsystem>/CS.cfg`

    ````
    selftests.container.order.startup=CAPresence:critical, SystemCertsVerification:critical
    ````

    **OR**

    Use the built-in tool:

    ````
    # pki-server selftest-disable -i <instance_name>
    ````
2. Synchronize NSS DB and CS.cfg

    ````
    # pki-server cert-update <cert ID> # for all system certificates that is to be renewed
    ````

### Bringing up the PKI server

1. Create temp SSL certificate
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

1. Renew required system certs using PKI tool:
    ````
    # pki-server cert-create --renew \
    -n <admin nickname> \
    -d <NSS db path> \
    -c <NSS client DB password>
    <cert ID> 
    --serial <serial No.> # Provide it from SSL server cert to avoid placing request for unintended cert
    ````
    **OR**

    using 3rd party tool (like certmonger). **Skip to step #4 after this step, if using this option**.
    ````
    # getcert list
    # getcert resubmit -i <id> # Get the ID of the tracked cert from the previous command
    ````

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
5. Enable the self test. Add the following highlighted line CS.cfg of the corresponding subsystem
    ````
    selftests.container.instance.CAPresence=com.netscape.cms.selftests.ca.CAPresence
    selftests.container.instance.CAValidity=com.netscape.cms.selftests.ca.CAValidity
    selftests.container.instance.SystemCertsVerification=com.netscape.cms.selftests.common.SystemCertsVerification
    selftests.container.order.onDemand=CAPresence:critical, SystemCertsVerification:critical, CAValidity:critical
    <font color="blue">selftests.container.order.startup=CAPresence:critical, SystemCertsVerification:critical</font>
    selftests.plugin.CAPresence.CaSubId=ca
    selftests.plugin.CAValidity.CaSubId=ca
    selftests.plugin.SystemCertsVerification.SubId=ca
    ````

    **OR** 

    Use the built-in tool available:
    ````
    # pki-server selftest-enable
    ````

6. Start server with new renewed system certificates.
    ````
    # systemctl start pki-tomcatd@pki-tomcat
    ````
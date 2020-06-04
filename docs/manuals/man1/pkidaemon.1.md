# pkidaemon 1 "Jul 8, 2015" PKI "pkidaemon"

## NAME

pkidaemon - provides status management of PKI instances

## SYNOPSIS

**pkidaemon** &lt;start|status&gt; &lt;*instance-name*&gt;

**Note:** Although this tool currently resides in the **/usr/bin** directory,
proper use of it requires it to be run with super user privileges.

## DESCRIPTION

The **pkidaemon status** argument provides a way to display the status of a PKI instance.

The **pkidaemon start** argument is currently only used internally by the systemctl scripts.

## EXAMPLES

For the following examples, two instances were installed. 
The first contained a CA, KRA, OCSP, TKS and TPS in a shared PKI instance named 'pki-tomcat',
while the second simply contained a CA running on different ports and named 'pki-tomcat-2'.

For the OCSP 'Unsecure URL' and the OCSP 'Secure EE URL'
which both specify a static string of '&lt;ocsp request blob&gt;',
the intention is for the user to replace this static string
with an actual OCSP request blob relevant to their particular deployment.

### Listing the status of the PKI instance named 'pki-tomcat':

```
$ pkidaemon status pki-tomcat

Status for pki-tomcat: pki-tomcat is running ..

    [CA Status Definitions]
    Unsecure URL        = http://pki.example.com:8080/ca/ee/ca
    Secure Agent URL    = https://pki.example.com:8443/ca/agent/ca
    Secure EE URL       = https://pki.example.com:8443/ca/ee/ca
    Secure Admin URL    = https://pki.example.com:8443/ca/services
    PKI Console Command = pkiconsole https://pki.example.com:8443/ca
    Tomcat Port         = 8005 (for shutdown)

    [KRA Status Definitions]
    Secure Agent URL    = https://pki.example.com:8443/kra/agent/kra
    Secure Admin URL    = https://pki.example.com:8443/kra/services
    PKI Console Command = pkiconsole https://pki.example.com:8443/kra
    Tomcat Port         = 8005 (for shutdown)

    [OCSP Status Definitions]
    Unsecure URL        = http://pki.example.com:8080/ocsp/ee/ocsp/<ocsp request blob>
    Secure Agent URL    = https://pki.example.com:8443/ocsp/agent/ocsp
    Secure EE URL       = https://pki.example.com:8443/ocsp/ee/ocsp/<ocsp request blob>
    Secure Admin URL    = https://pki.example.com:8443/ocsp/services
    PKI Console Command = pkiconsole https://pki.example.com:8443/ocsp
    Tomcat Port         = 8005 (for shutdown)

    [TKS Status Definitions]
    Secure Agent URL    = https://pki.example.com:8443/tks/agent/tks
    Secure Admin URL    = https://pki.example.com:8443/tks/services
    PKI Console Command = pkiconsole https://pki.example.com:8443/tks
    Tomcat Port         = 8005 (for shutdown)

    [TPS Status Definitions]
    Unsecure URL        = http://pki.example.com:8080/tps
    Secure URL          = https://pki.example.com:8443/tps
    Unsecure PHONE HOME = http://pki.example.com:8080/tps/phoneHome
    Secure PHONE HOME   = https://pki.example.com:8443/tps/phoneHome
    Tomcat Port         = 8005 (for shutdown)

    [CA Configuration Definitions]
    PKI Instance Name:   pki-tomcat

    PKI Subsystem Type:  Root CA (Security Domain)

    Registered PKI Security Domain Information:
    ====================================================================
    Name:  example.com Security Domain
    URL:   https://pki.example.com:8443
    ====================================================================

    [KRA Configuration Definitions]
    PKI Instance Name:   pki-tomcat

    PKI Subsystem Type:  KRA

    Registered PKI Security Domain Information:
    ====================================================================
    Name:  example.com Security Domain
    URL:   https://pki.example.com:8443
    ====================================================================

    [OCSP Configuration Definitions]
    PKI Instance Name:   pki-tomcat

    PKI Subsystem Type:  OCSP

    Registered PKI Security Domain Information:
    ====================================================================
    Name:  example.com Security Domain
    URL:   https://pki.example.com:8443
    ====================================================================

    [TKS Configuration Definitions]
    PKI Instance Name:   pki-tomcat

    PKI Subsystem Type:  TKS

    Registered PKI Security Domain Information:
    ====================================================================
    Name:  example.com Security Domain
    URL:   https://pki.example.com:8443
    ====================================================================

    [TPS Configuration Definitions]
    PKI Instance Name:   pki-tomcat

    PKI Subsystem Type:  TPS

    Registered PKI Security Domain Information:
    ====================================================================
    Name:  example.com Security Domain
    URL:   https://pki.example.com:8443
    ====================================================================
```

### Listing the status of the PKI instance named 'pki-tomcat-2':

```
$ pkidaemon status pki-tomcat-2

Status for pki-tomcat-2: pki-tomcat-2 is running ..

    [CA Status Definitions]
    Unsecure URL        = http://pki.example.com:18080/ca/ee/ca
    Secure Agent URL    = https://pki.example.com:18443/ca/agent/ca
    Secure EE URL       = https://pki.example.com:18443/ca/ee/ca
    Secure Admin URL    = https://pki.example.com:18443/ca/services
    PKI Console Command = pkiconsole https://pki.example.com:18443/ca
    Tomcat Port         = 18005 (for shutdown)

    [CA Configuration Definitions]
    PKI Instance Name:   pki-tomcat-2

    PKI Subsystem Type:  Root CA (Security Domain)

    Registered PKI Security Domain Information:
    ====================================================================
    Name:  example.com Security Domain
    URL:   https://pki.example.com:18443
    ====================================================================
```

## SEE ALSO

**pkispawn(8)**  
**pkidestroy(8)**  
**pki_default.cfg(5)**  
**pki(1)**

## AUTHORS

Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2015 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

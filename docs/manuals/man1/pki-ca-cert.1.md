# pki-cert 1 "May 5, 2014" PKI "PKI Certificate Management Commands"

## NAME

pki-ca-cert - Command-line interface for managing certificates on PKI CA.

## SYNOPSIS

**pki** [*CLI-options*] **ca-cert**  
**pki** [*CLI-options*] **ca-cert-find** [*command-options*]  
**pki** [*CLI-options*] **ca-cert-show** *cert-ID* [*command-options*]  
**pki** [*CLI-options*] **ca-cert-revoke** *cert-ID* [*command-options*]  
**pki** [*CLI-options*] **ca-cert-hold** *cert-ID* [*command-options*]  
**pki** [*CLI-options*] **ca-cert-release-hold** *cert-ID* [*command-options*]  
**pki** [*CLI-options*] **ca-cert-request-profile-find** [*command-options*]  
**pki** [*CLI-options*] **ca-cert-request-profile-show** *profile-ID* [*command-options*]  
**pki** [*CLI-options*] **ca-cert-request-submit** [*command-options*]  
**pki** [*CLI-options*] **ca-cert-request-review** *request-ID* [*command-options*]  

## DESCRIPTION

The **pki-cert** commands provide command-line interfaces to manage certificates on the CA.

**pki** [*CLI-options*] **ca-cert**  
    This command is to list available certificate commands.

**pki** [*CLI-options*] **ca-cert-find** [*command-options*]  
    This command is to list certificates in the CA.

**pki** [*CLI-options*] **ca-cert-show** *cert-ID* [*command-options*]  
    This command is to view a certificate details.

**pki** [*CLI-options*] **ca-cert-revoke** *cert-ID*  
    This command is to revoke a certificate.

**pki** [*CLI-options*] **ca-cert-hold** *cert-ID*  
    This command is to place a certificate on hold temporarily.

**pki** [*CLI-options*] **ca-cert-release-hold** *cert-ID*  
    This command is to release a certificate that has been placed on hold.

**pki** [*CLI-options*] **ca-cert-request-profile-find** [*command-options*]  
    This command is to list available certificate request templates.

**pki** [*CLI-options*] **ca-cert-request-profile-show** *profile-ID* [*command-options*]  
    This command is to view a certificate request template.

**pki** [*CLI-options*] **ca-cert-request-submit** [*command-options*]  
    This command is to submit a certificate request.

**pki** [*CLI-options*] **ca-cert-request-review** *request-ID* [*command-options*]  
    This command is to review a certificate request.

## OPTIONS

The *command-options* are described in **pki(1)**.

## OPERATIONS

To view available certificate commands, type **pki ca-cert**.
To view each command's usage, type **pki ca-cert-&lt;command&gt; --help**.

### Viewing Certificates

Certificates can be viewed anonymously.

To list all certificates in the CA:

```
$ pki ca-cert-find
```

It is also possible to search for and list specific certificates by adding a search filter.
Use **pki ca-cert-find --help** to see options.  For example, to search based on issuance date:

```
$ pki ca-cert-find --issuedOnFrom 2012-06-15
```

To list certificates with search constraints defined in a file:

```
$ pki ca-cert-find --input <filename>
```

where the file is in the following format:

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<CertSearchRequest>

    <serialNumberRangeInUse>true</serialNumberRangeInUse>
    <serialFrom></serialFrom>
    <serialTo></serialTo>

    <subjectInUse>false</subjectInUse>
    <eMail></eMail>
    <commonName></commonName>
    <userID></userID>
    <orgUnit></orgUnit>
    <org></org>
    <locality></locality>
    <state></state>
    <country></country>

    <matchExactly>false</matchExactly>

    <status></status>

    <revokedByInUse>false</revokedByInUse>
    <revokedBy></revokedBy>

    <revokedOnFrom>false</revokedOnFrom>
    <revokedOnTo></revokedOnTo>

    <revocationReasonInUse>false</revocationReasonInUse>
    <revocationReason></revocationReason>

    <issuedByInUse>false</issuedByInUse>
    <issuedBy></issuedBy>

    <issuedOnInUse>false</issuedOnInUse>
    <issuedOnFrom></issuedOnFrom>
    <issuedOnTo></issuedOnTo>

    <validNotBeforeInUse>false</validNotBeforeInUse>
    <validNotBeforeFrom></validNotBeforeFrom>
    <validNotBeforeTo></validNotBeforeTo>

    <validNotAfterInUse>false</validNotAfterInUse>
    <validNotAfterFrom></validNotAfterFrom>
    <validNotAfterTo></validNotAfterTo>

    <validityLengthInUse>false</validityLengthInUse>
    <validityOperation></validityOperation>
    <validityCount></validityCount>
    <validityUnit></validityUnit>

    <certTypeInUse>false</certTypeInUse>
    <certTypeSubEmailCA></certTypeSubEmailCA>
    <certTypeSubSSLCA></certTypeSubSSLCA>
    <certTypeSecureEmail></certTypeSecureEmail>

</CertSearchRequest>
```

To view a particular certificate:

```
$ pki ca-cert-show <certificate ID>
```

### Revoking Certificates

Revoking, holding, or releasing a certificate must be executed as an agent user.
To revoke a certificate:

```
$ pki <agent authentication> ca-cert-revoke <certificate ID>
```

To place a certificate on hold temporarily:

```
$ pki <agent authentication> ca-cert-hold <certificate ID>
```

To release a certificate that has been placed on hold:

```
$ pki <agent authentication> ca-cert-release-hold <certificate ID>
```

### Certificate Requests

To request a certificate, first generate a certificate signing request (CSR), then submit it with a certificate profile.
The list of available profiles can be viewed using the following command:

```
$ pki ca-cert-request-profile-find
```

To generate a CSR, use the certutil, PKCS10Client, or CRMFPopClient, and store it into a file.

Basic requests can be submitted using the following command:

```
$ pki ca-cert-request-submit \
    --profile <profile ID> --request-type <type> --csr-file <CSR file> --subject <subject DN>
```

To submit more advanced requests, download a template of the request file for a particular profile using the following command:

```
$ pki ca-cert-request-profile-show <profile ID> --output <request file>
```

Then, edit the request file, fill in the input attributes required by the profile, and submit the request using the following command:

```
$ pki ca-cert-request-submit <request file>
```

Depending on the profile, the command may require authentication (see the profile configuration file).
The CLI currently supports client certificate authentication and directory-based authentication.

To submit the certificate renewal request can be submitted using the following command:

```
$ pki ca-cert-request-submit --profile <Renewal Profile> --serial <Certificate ID> --renewal
```

Also depending on the profile, an agent may need to review and approve the request by running
the following command:

```
$ pki <agent authentication> ca-cert-request-review <request ID> \
    --file <file to store the certificate request>
```

The **--file** and **--action** options are mutually exclusive
(i.e. only one or the other may be specified during command invocation).

If the **--file** option is specified, the certificate request,
as well as the defaults and constraints of the enrollment profile,
will be retrieved and stored in the output file provided by the **--file** option.
The agent can examine the file and override any values if necessary.
To process the request, enter the appropriate action when prompted:

```
Action (approve/reject/cancel/update/validate/assign/unassign):
```

The request in the file will be read in, and the specified action will be applied against it.

Alternatively, when no changes to the request are necessary,
the agent can process the request in a single step using the **--action** option with the following command:

```
$ pki <agent authentication> ca-cert-request-review <request ID> --action <action>
```

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;, Endi S. Dewata &lt;edewata@redhat.com&gt;, and Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

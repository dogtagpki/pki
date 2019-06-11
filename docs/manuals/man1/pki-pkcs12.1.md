# pki-pkcs12 1 "Oct 28, 2016" PKI "PKI PKCS #12 Management Commands"

## NAME

pki-pkcs12 - Command-line interface for managing certificates and keys in PKCS #12 file.

## SYNOPSIS

**pki** [*CLI-options*] **pkcs12**  
**pki** [*CLI-options*] **pkcs12-export** [*command-options*]  
**pki** [*CLI-options*] **pkcs12-import** [*command-options*]  
**pki** [*CLI-options*] **pkcs12-cert** [*command-options*]  
**pki** [*CLI-options*] **pkcs12-key** [*command-options*]  

## DESCRIPTION

The **pki pkcs12** commands provide command-line interfaces to manage certificate and keys in a PKCS #12 file.

**pki** [*CLI-options*] **pkcs12-export** [*command-options*]  
    This command is to export all certificates and keys from an NSS database into a PKCS #12 file.

**pki** [*CLI-options*] **pkcs12-import** [*command-options*]  
    This command is to import all certificates and keys from a PKCS #12 file into an NSS database.

**pki** [*CLI-options*] **pkcs12-cert** [*command-options*]  
    This command is to manage individual certificates in a PKCS #12 file. See **pki-pkcs12-cert(1)**.

**pki** [*CLI-options*] **pkcs12-key** [*command-options*]  
    This command is to import individual keys in a PKCS #12 file. See **pki-pkcs12-key(1)**.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available PKCS #12 commands, type **pki pkcs12**.
To view each command's usage, type **pki pkcs12-&lt;command&gt; --help**.

All **pki pkcs12** commands require a PKCS #12 file and its password.
The PKCS #12 file can be specified with the **--pkcs12-file** parameter.
The password can be specified either directly with the **--pkcs12-password** parameter,
or in a file with the **--pkcs12-password-file** parameter.

Some **pki pkcs12** commands require an NSS database and its password.
The NSS database location can be specified with the **-d** parameter (default: ~/.dogtag/nssdb).
The NSS database password can be specified with the **-c** or the **-C** parameter.

### Exporting all certificates and keys into a PKCS #12 file

To export all certificates and keys from an NSS database into a PKCS #12 file:

```
$ pki <NSS database location> <NSS database password> pkcs12-export \
    <PKCS #12 file> <PKCS #12 password> [nicknames...]
```

By default the command will export all certificates in the NSS database.
To export certain certificates only, specify the certificate nicknames as separate arguments.

By default the command will always create a new PKCS #12 file.
To export into an existing PKCS #12 file, specify the **--append** parameter.

By default the command will include the certificate chain.
To export without certificate chain, specify the **--no-chain** parameter.

By default the command will include the key of each certificate.
To export without the key, specify the **--no-key** parameter.

By default the command will include the trust flags of each certificate.
To export without the trust flags, specify the **--no-trust-flags** parameter.

### Importing certificates and keys from a PKCS #12 file

To import certificates and keys from a PKCS #12 file into an NSS database:

```
$ pki <NSS database location> <NSS database password> pkcs12-import \
    <PKCS #12 file> <PKCS #12 password>
```

By default the command will include all certificates in the PKCS #12 file.
To import without the CA certificates (certificates without keys), specify the **--no-ca-certs** parameter.
To import without the user certificates (certificates with keys), specify the **--no-user-certs** parameter.

By default the command will skip a certificate if it already exists in the NSS database.
To overwrite the nickname, the key, and the trust flags of existing certificates, specify the **--overwrite** parameter.

By default the command will include the trust flags of each certificate.
To import without the trust flags, specify the **--no-trust-flags** parameter.

## SEE ALSO

**pki-pkcs12-cert(1)**, **pki-pkcs12-key(1)**

## AUTHORS

Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2016 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

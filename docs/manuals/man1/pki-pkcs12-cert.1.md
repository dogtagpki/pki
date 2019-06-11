# pki-pkcs12-cert 1 "Oct 28, 2016" PKI "PKI PKCS #12 Certificate Management Commands"

## NAME

pki-pkcs12-cert - Command-line interface for managing individual certificates in PKCS #12 file.

## SYNOPSIS

**pki** [*CLI-options*] **pkcs12-cert**  
**pki** [*CLI-options*] **pkcs12-cert-find** [*command-options*]  
**pki** [*CLI-options*] **pkcs12-cert-export** *nickname* [*command-options*]  
**pki** [*CLI-options*] **pkcs12-cert-import** *nickname* [*command-options*]  
**pki** [*CLI-options*] **pkcs12-cert-mod** *nickname* [*command-options*]  
**pki** [*CLI-options*] **pkcs12-cert-del** *nickname* [*command-options*]  

## DESCRIPTION

The **pki pkcs12-cert** commands provide command-line interfaces to manage certificates in a PKCS #12 file.

**pki** [*CLI-options*] **pkcs12-cert-find** [*command-options*]  
    This command is to list certificates in a PKCS #12 file.

**pki** [*CLI-options*] **pkcs12-cert-export** *nickname* [*command-options*]  
    This command is to export a certificate from a PKCS #12 file.

**pki** [*CLI-options*] **pkcs12-cert-import** *nickname* [*command-options*]  
    This command is to import a certificate into a PKCS #12 file.

**pki** [*CLI-options*] **pkcs12-cert-mod** *nickname* [*command-options*]  
    This command is to modify a certificate in a PKCS #12 file.

**pki** [*CLI-options*] **pkcs12-cert-del** *nickname* [*command-options*]  
    This command is to delete a certificate from a PKCS #12 file.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available profile commands, type **pki pkcs12-cert**.
To view each command's usage, type **pki pkcs12-cert-&lt;command&gt; --help**.

All **pki pkcs12-cert** commands require a PKCS #12 file and its password.
The PKCS #12 file can be specified with the **--pkcs12-file** parameter.
The password can be specified either directly with the **--pkcs12-password** parameter,
or in a file with the **--pkcs12-password-file** parameter.

Some **pki pkcs12-cert** commands require an NSS database and its password.
The NSS database location can be specified with the **-d** parameter (default: ~/.dogtag/nssdb).
The NSS database password can be specified with the **-c** or the **-C** parameter.

### Viewing certificates in a PKCS #12 file

To list the certificates in a PKCS #12 file:

```
$ pki pkcs12-cert-find <PKCS #12 file> <PKCS #12 password>
```

### Exporting a certificate from a PKCS #12 file

To export a certificate from a PKCS #12 file into a file in PEM format:

```
$ pki pkcs12-cert-export <nickname> <PKCS #12 file> <PKCS #12 password> <cert file>
```

The certificate file can be specified with the **--cert-file** parameter.

### Importing a certificate into a PKCS #12 file

To import a certificate including its key and trust flags from an NSS database into a PKCS #12 file:

```
$ pki <NSS database location> <NSS database password> pkcs12-cert-import <nickname> \
    <PKCS #12 file> <PKCS #12 password>
```

If the PKCS #12 file does not exist, it will be created automatically.
If the PKCS #12 file already exists, the certificate will be added into the file.

The trust flags can be overwritten with the **--trust-flags** parameter.
If the key is not needed, specify the **--no-key** parameter.

### Modifying a certificate in a PKCS #12 file

To modify the trust flags of a certificate in a PKCS #12 file:

```
$ pki pkcs12-cert-mod <nickname> <PKCS #12 file> <PKCS #12 password> <trust flags>
```

The trust flags can be specified with the **--trust-flags** parameter.

### Deleting a certificate from a PKCS #12 file

To delete a certificate and its key from a PKCS #12 file:

```
$ pki pkcs12-cert-del <nickname> <PKCS #12 file> <PKCS #12 password>
```

## SEE ALSO

**pki-pkcs12(1)**

## AUTHORS

Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2016 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

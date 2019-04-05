# pki-pkcs12-key 1 "Oct 28, 2016" PKI "PKI PKCS #12 Key Management Commands"

## NAME

pki-pkcs12-key - Command-line interface for managing individual keys in PKCS #12 file.

## SYNOPSIS

**pki** [*CLI-options*] **pkcs12-key**  
**pki** [*CLI-options*] **pkcs12-key-find** [*command-options*]  
**pki** [*CLI-options*] **pkcs12-key-del** *key-ID* [*command-options*]  

## DESCRIPTION

The **pki pkcs12-key** commands provide command-line interfaces to manage keys in a PKCS #12 file.

**pki** [*CLI-options*] **pkcs12-key-find** [*command-options*]  
    This command is to list keys in a PKCS #12 file.

**pki** [*CLI-options*] **pkcs12-key-del** *key-ID* [*command-options*]  
    This command is to delete a key from a PKCS #12 file.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available profile commands, type **pki pkcs12-key**.
To view each command's usage, type **pki pkcs12-key-&lt;command&gt; --help**.

All **pki pkcs12-key** commands require a PKCS #12 file and its password.
The PKCS #12 file can be specified with the **--pkcs12-file** parameter.
The password can be specified either directly with the **--pkcs12-password** parameter,
or in a file with the **--pkcs12-password-file** parameter.

All **pki pkcs12-key** commands also require an NSS database and its password.
The NSS database location can be specified with the **-d** parameter (default: ~/.dogtag/nssdb).
The NSS database password can be specified with the **-c** or the **-C** parameter.

### Viewing keys in a PKCS #12 file

To list the keys in a PKCS #12 file:

```
$ pki <NSS database location> <NSS database password> pkcs12-key-find \
    <PKCS #12 file> <PKCS #12 password>
```

### Deleting a key from a PKCS #12 file

To delete a key from a PKCS #12 file:

```
$ pki <NSS database location> <NSS database password> pkcs12-key-del <key ID> \
    <PKCS #12 file> <PKCS #12 password>
```

## SEE ALSO

**pki-pkcs12(1)**

## AUTHORS

Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2016 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

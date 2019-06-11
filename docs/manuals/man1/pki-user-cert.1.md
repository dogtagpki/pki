# pki-user-cert 1 "Jun 3, 2015" PKI "PKI User Certificate Management Commands"

## NAME

pki-user-cert - Command-line interface for managing PKI user certificates.

## SYNOPSIS

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert**  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert-find** *user-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert-show** *user-ID* *cert-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert-add** *user-ID* [*command-options*]  
**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert-del** *user-ID* *cert-ID* [*command-options*]  

## DESCRIPTION

The **pki &lt;subsystem&gt;-user-cert** commands provide command-line interfaces to manage user certificates on the specified subsystem.

Valid subsystems are **ca**, **kra**, **ocsp**, **tks**, and **tps**.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert**  
    This command is to list available user certificate commands for the subsystem.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert-find** *user-ID* [*command-options*]  
    This command is to list certificates owned by the subsystem user.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert-show** *user-ID* *cert-ID* [*command-options*]  
    This command is to view the details of a certificate owned to the subsystem user.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert-add** *user-ID* [*command-options*]  
    This command is to add a certificate to the subsystem user.

**pki** [*CLI-options*] **&lt;subsystem&gt;-user-cert-del** *user-ID* *cert-ID* [*command-options*]  
    This command is to delete a certificate from the subsystem user.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available user certificate commands, type **pki &lt;subsystem&gt;-user-cert**.
To view each command's usage, type **pki &lt;subsystem&gt;-user-cert-&lt;command&gt; --help**.

All user certificate commands must be executed as the subsystem administrator.

For example, to list certificates owned by a CA user execute the following command:

```
$ pki <CA admin authentication> ca-user-cert-find testuser
```

The results can be paged by specifying the (0-based) index of the first entry to return and the maximum number of entries returned:

```
$ pki <CA admin authentication> ca-user-cert-find testuser --start 20 --size 10
```

The above command will return entries #20 to #29.

To view a certificate owned by a CA user, specify the user ID and the certificate ID in the following command:

```
$ pki <CA admin authentication> ca-user-cert-show testuser \
    "2;11;CN=CA Signing Certificate,O=EXAMPLE;UID=testuser"
```

To add a certificate to a CA user from a file, specify the user ID and the input file:

```
$ pki <CA admin authentication> ca-user-cert-add testuser --input testuser.crt
```

To add a certificate to a CA user from the certificate repository, specify the user ID and the serial number:

```
$ pki <CA admin authentication> ca-user-cert-add testuser --serial 0x80
```

To delete a certificate from a CA user, specify the user ID and the certificate ID in the following command:

```
$ pki <CA admin authentication> ca-user-cert-del testuser \
    "2;11;CN=CA Signing Certificate,O=EXAMPLE;UID=testuser"
```

## AUTHORS

Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2015 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

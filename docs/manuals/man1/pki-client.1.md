# pki-client 1 "May 5, 2014" PKI "PKI NSS Database Management Commands"

## NAME

pki-client - Command-line interface for managing the NSS database on PKI client.

## SYNOPSIS

**pki** [*CLI-options*] **client**  
**pki** [*CLI-options*] **client-init** [*command-options*]  
**pki** [*CLI-options*] **client-cert-find** [*command-options*]  
**pki** [*CLI-options*] **client-cert-request** [*subject-DN*] [*command-options*]  
**pki** [*CLI-options*] **client-cert-import** [*nickname*] [*command-options*]  
**pki** [*CLI-options*] **client-cert-mod** *nickname* [*command-options*]  
**pki** [*CLI-options*] **client-cert-show** *nickname* [*command-options*]  
**pki** [*CLI-options*] **client-cert-del** *nickname* [*command-options*]  

## DESCRIPTION

The **pki-client** commands provide command-line interfaces to manage the NSS database on the client's machine.

**pki** [*CLI-options*] **client**  
    This command is to list available client commands.

**pki** [*CLI-options*] **client-init** [*command-options*]  
    This command is to create a new NSS database for the client.

**pki** [*CLI-options*] **client-cert-find** [*command-options*]  
    This command is to list certificates in the NSS database.

**pki** [*CLI-options*] **client-cert-request** [*subject-DN*] [*command-options*]  
    This command is to generate and submit a certificate request.

**pki** [*CLI-options*] **client-cert-import** [*nickname*] [*command-options*]  
    This command is to import a certificate into the NSS database.

**pki** [*CLI-options*] **client-cert-mod** *nickname* [*command-options*]  
    This command is to modify a certificate in the NSS database.

**pki** [*CLI-options*] **client-cert-show** *nickname* [*command-options*]  
    This command is to view a certificate in the NSS database.

**pki** [*CLI-options*] **client-cert-del** *nickname* [*command-options*]  
    This command is to delete a certificate from the NSS database.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available client commands, type **pki client**.
To view each command's usage, type **pki client-&lt;command&gt; --help**.

To create a new database execute the following command:

```
$ pki -d <NSS database location> -c <NSS database password> client-init
```

To list certificates in the NSS database:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-find
```

To request a certificate:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-request [subject DN]
```

The subject DN requirement depends on the certificate profile being requested.
Some profiles may require the user to provide a subject DN in a certain format.
Some other profiles may generate their own subject DN.

Certain profiles may also require additional authentication.
To authenticate, a username and a password can be specified using the **--username** and **--password** options, respectively.
If the subject DN is not specififed the CLI may use the username to generate a default subject DN "UID=*username*".

To import a certificate from a file into the NSS database:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-import [*nickname*] \
    --cert <path>
```

To import a CA certificate from a file into the NSS database:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-import <nickname> \
    --ca-cert <path>
```

To import certificates and private keys from a PKCS #12 file into the NSS database:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-import \
    --pkcs12 <path> --pkcs12-password <password>
```

To import a certificate from CA server into the NSS database:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-import <nickname> \
    --serial <serial number>
```

To import a CA certificate from CA server into the NSS database:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-import <nickname> \
    --ca-server
```

To modify a certificate's trust attributes in the NSS database:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-mod <nickname> \
    --trust <trust attributes>
```

To display a certificate in the NSS database:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-show <nickname>
```

To export a certificate from the NSS database into a PEM file:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-show <nickname> \
    --cert <path>
```

To export a certificate chain with the private key from the NSS database into a PKCS #12 file:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-show <nickname> \
    --pkcs12 <path> --pkcs12-password <password>
```

To export a certificate chain with the private key with a password file:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-show <nickname> \
    --pkcs12 <path> --pkcs12-password-file <path>
```

To export a client certificate with the private key from the NSS database into a PEM file:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-show <nickname> \
    --client-cert <path>
```

To delete a certificate from the NSS database:

```
$ pki -d <NSS database location> -c <NSS database password> client-cert-del <nickname>
```

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;, Endi Dewata &lt;edewata@redhat.com&gt;, and Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

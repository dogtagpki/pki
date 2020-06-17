# pki 1 "February 1, 2019" PKI "pki CLI"

## NAME

pki - Command-Line Interface for accessing PKI services.

## SYNOPSIS

**pki** [*CLI-options*] *command* [*command-arguments*]

## DESCRIPTION

The **pki** command provides a command-line interface allowing clients
to access various services on the PKI server.
These services include certificates, groups, keys, security domains, and users.

## CLI OPTIONS

**-c** *NSS-database-password*  
    Specifies the NSS database password (mutually exclusive to the **-C** option).

**-C** *NSS-database-password-file*  
    Specifies the file which contains the NSS database password (mutually exclusive to the **-c** option).

**-d** *NSS-database-location*  
    Specifies the NSS database location (default: *&#8764;/.dogtag/nssdb*).

**-h** *hostname*  
    Specifies the hostname (default: hostname of the local machine).

**--help**  
    Prints additional help information.

**--ignore-cert-status** *list*  
    Comma-separated list of ignored certificate validity statuses. Valid values are:

- BAD_CERT_DOMAIN
- BAD_KEY
- BAD_SIGNATURE
- CA_CERT_INVALID
- CERT_BAD_ACCESS_LOCATION
- CERT_NOT_IN_NAME_SPACE
- CERT_STATUS_SERVER_ERROR
- EXPIRED_CERTIFICATE
- EXPIRED_ISSUER_CERTIFICATE
- INADEQUATE_CERT_TYPE
- INADEQUATE_KEY_USAGE
- INVALID_TIME
- OCSP_BAD_HTTP_RESPONSE
- OCSP_FUTURE_RESPONSE
- OCSP_MALFORMED_REQUEST
- OCSP_MALFORMED_RESPONSE
- OCSP_NO_DEFAULT_RESPONDER
- OCSP_NOT_ENABLED
- OCSP_OLD_RESPONSE
- OCSP_REQUEST_NEEDS_SIG
- OCSP_SERVER_ERROR
- OCSP_TRY_SERVER_LATER
- OCSP_UNAUTHORIZED_REQUEST
- OCSP_UNKNOWN_CERT
- OCSP_UNKNOWN_RESPONSE_STATUS
- OCSP_UNKNOWN_RESPONSE_TYPE
- OCSP_UNAUTHORIZED_RESPONSE
- PATH_LEN_CONSTRAINT_INVALID
- REVOKED_CERTIFICATE
- SEC_ERROR_CRL_BAD_SIGNATURE
- SEC_ERROR_CRL_EXPIRED
- SEC_ERROR_CRL_INVALID
- UNKNOWN_ISSUER
- UNKNOWN_SIGNER
- UNTRUSTED_CERT
- UNTRUSTED_ISSUER

**--message-format** *format*  
    Message format: xml (default), json.

**-n** *client-certificate-nickname*  
    Specifies the nickname for client certificate authentication (mutually exclusive to the **-u** option).

**--output** *folder*  
    Folder to store HTTP messages.

**-P** *protocol*  
    Specifies the protocol (default: http).

**-p** *port*  
    Specifies the port (default: 8080).

**--reject-cert-status** *list*  
    Comma-separated list of rejected certificate validity statuses.

**-t** *type*  
    Subsystem type.

**--token** *token*  
    Security token name

**-U** *URL*  
    Specifies the server URL.

**-u** *username*  
    Specifies the username for basic authentication (mutually exclusive to the **-n** option).

**-v**, **--verbose**  
    Displays verbose information.

**--version**  
    Displays CLI version information.

**-w** *password*  
    Specifies the user password (mutually exclusive to the **-W** option).

**-W** *client-side-password-file*  
    Specifies the file which contains the user password (mutually exclusive to the **-w** option).

## OPERATIONS

To view available commands and options, simply type **pki**.  Some commands have sub-commands.
To view the sub-commands, type **pki *command***.
To view each command's usage, type **pki *command* --help**.

An NSS database is needed to execute commands that require crypto operations such as establishing SSL connection.
See **pki-client(1)** for more information.

### Connection

By default, the CLI connects to a server running on the local machine via the non-secure HTTP port 8080.
To specify a different server location, use the appropriate arguments to give a different host (**-h**), port (**-p**), or connection protocol (**-P**).

```
$ pki -P <protocol> -h <hostname> -p <port> <command>
```

Alternatively, the connection parameters can be specified as a URI:

```
$ pki -U <URI> <command>
```

where the URI is of the format *protocol*://*hostname*:*port*.

## Authentication

Some commands require authentication. These are commands that are restricted
to particular sets of users (such as agents or admins) or those operations
involving certificate profiles that require authentication.

To execute a command without authentication:

```
$ pki <command>
```

To execute a command using basic authentication (i.e. username/password), see the **Basic Authentication** section of this man page.

To execute a command using client authentication (i.e. client certificate), see the **Client Authentication** section of this man page.

### Basic Authentication

To authenticate with a username and password:

```
$ pki -u <username> -w <password> <command>
```

Rather than being exposed in plaintext on the command-line, user passwords may be stored in a file instead.
See **Client-side Password Files** for detailed information.

To authenticate with a username by obtaining the user password from a client-side password file:

```
$ pki -u <username> -W <client-side password file> <command>
```

Finally, if a username has been specified on the command-line,
and neither the **-W** *client-side-password-file* nor the **-w** *password* options have been utilized,
the password will be prompted for.

To authenticate with a username by interactively prompting for a password:

```
$ pki -u <username> <command>
```

**Note:** Prompting for a user password is not suitable for automated batch processing.

### Client Authentication Setup

A client certificate associated with the desired PKI server must be used for
client authentication. This can be done by importing the client certificate
into an NSS security database and passing the values to the relevant options
provided by the **pki** CLI framework.

To achieve this, execute the following commands to set up an NSS database for use by the **pki** client,
import the client certificate into the NSS database, and list information
(including the nickname of the client certificate) stored in the NSS database:

```
$ certutil -N -d <NSS database location>
$ pk12util -i <client's PKCS #12 file> -d <NSS database location>
$ certutil -L -d <NSS database location>
```

The first command creates an NSS database, and asks the client user to enter a password for this NSS database.

The second command imports a client certificate stored in a PKCS #12 format into this NSS database;
it prompts for the passwords of the PKCS12 file and the NSS database.
The simplest example of such a client certificate is to obtain the administrator certificate
created during the configuration portion of the basic PKI installation of the associated PKI server
(e.g. located at */root/.dogtag/pki-tomcat/ca_admin_cert.p12* on the PKI server machine).

The third command shows the information about the imported client certificate (including its nickname).

Additionally, provision the root CA certificate into this NSS DB.
This certificate must be imported into the NSS DB and copied as a PEM format
certificate into the NSS DB directory, named 'ca.crt'.
To do so:

```
$ certutil -A -d <NSS database location> -n "CA Root Certificate" -a -i /path/to/ca.crt
$ cp /path/to/ca.crt <NSS database location>/ca.crt
```

This will ensure all parts of the client can successfully connect with the
PKI instance and validate the certificate used to sign the web UI. If an
external CA certificate was used to approve the sslserver certificate, import
that certificate instead.

### Client Authentication

To authenticate with a client certificate:

```
$ pki -d <NSS database location> -c <NSS database password> -n <client certificate nickname> <command>
```

Alternatively, to prevent exposure via the command-line, an NSS database may store their password in a file instead.
See **Client-side Password Files** for detailed information.

To authenticate with a client certificate by using the NSS database password stored in a file:

```
$ pki -d <NSS database location> -C <NSS password file> -n <client certificate nickname> <command>
```

Finally, if a client certificate has been specified on the command-line,
and neither the **-C** *NSS-database-password-file* nor the **-c** *NSS-database-password* options have been utilized,
the NSS database password will be prompted for.

To authenticate with a client certificate by interactively prompting for an NSS database password:

```
$ pki -d <NSS database location> -n <client certificate nickname> <command>
```

**Note:** Prompting for an NSS database password is not suitable for automated batch processing.

### Client-side Password Files

Both the **-C** (client authentication) and the **-W** (basic authentication) options require the use of a client-side password file.

For security purposes, client-side password files should be, at a minimum, operating system protected non-world readable files.

Client-side password files generally store a password in an equals-sign-delimited plaintext format 'token=password'
(e.g. 'internal=foobar' where 'internal' is the token, '=' is the delimiter, and 'foobar' is the actual password).
The token keyword 'internal' is the default specification for a token, and refers to the "Internal Key Storage Token".
If a client-side password file is being used for the sole purposes of the **pki** command-line tool,
a client-side password file also supports the format that merely consists of the plaintext password on a single line
(read the **Caveats** which follow).

**Caveats:**

Since client-side password files are allowed to use the 'token=password' format, the first '=' character can only be used as a delimiter
(i.e. it cannot be used as a valid character within the 'token' name) as escaping the '=' character within a token is not supported.

When specifying a password which contains an '=' character, always specify an initial '=' prior to specifying the actual password
(mandatory when no token has been specified) as escaping the '=' character within a password is not supported.

Tokens do not support leading or trailing whitespace since these characters are stripped prior to their use;
however, all whitespace inside tokens will be preserved.

Passwords preserve all leading, trailing, and internal whitespace since passwords are not trimmed prior to their use.

TBD: Supply code to handle the case of a non-internal token (e.g. 'hardware-nethsm' utilized in the following examples)
since the current code ignores the specified token (i.e. it always utilizes the default 'internal' token no matter what is currently specified).

TBD: Allow numerous 'token=password' lines in a single client-side password file to support the ability to authenticate against specified tokens as well as multiple tokens.

### Valid examples include:

**internal=foobar**  
    where token="internal" and password="foobar"

**hardware-nethsm=foobar**  
    where token="hardware-nethsm" (ignored - TBD) and password="foobar"

**internal=ack=bar**  
    where token="internal" and password="ack=bar"

**hardware-nethsm=ack=bar**  
    where and token="hardware-nethsm" (ignored - TBD) and password="ack=bar"

**=foobar**  
    where token="internal" (default) and password="foobar"

**=foo=bar**  
    where token="internal" (default) and password="foo=bar"
    (Since the password contains an '=' character, an initial '=' character must be specified!)

**foobar**  
    where token="internal" (default) and password="foobar"

### Results Paging

Some commands (e.g. cert-find) may return multiple results. Since the number
of results may be large, the results are split into multiple pages. By default
the command will return only the first page (e.g. the first 20 results). To
retrieve results from another page, additional paging parameters can be
specified:

- start: index of the first result to return (default: 0)
- size: number of results to return (default: 20)

For example, to retrieve the first page (index #0-#19):

```
$ pki cert-find --start 0 --size 20
```

To retrieve the second page (index #20-#39):

```
$ pki cert-find --start 20 --size 20
```

To retrieve the third page (index #40-#59):

```
$ pki cert-find --start 40 --size 20
```

## FILES

*/usr/bin/pki*

## SEE ALSO

**pki-cert(1)**  
    Certificate management commands

**pki-client(1)**  
    NSS database management commands

**pki-group(1)**  
    Group management commands

**pki-group-member(1)**  
    Group member management commands

**pki-key(1)**  
    Key management commands

**pki-securitydomain(1)**  
    Security domain management commands

**pki-user(1)**  
    User management commands

**pki-user-cert(1)**  
    User certificate management commands

**pki-user-membership(1)**  
    User membership management commands

**pki-ca-profile(1)**  
    Profile management commands

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;, Endi Dewata &lt;edewata@redhat.com&gt;, and Matthew Harmsen &lt;mharmsen@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2012 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

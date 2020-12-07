# pki-kra-key 1 "May 5, 2014" PKI "PKI KRA Key Management Commands"

## NAME

pki-key - Command-line interface for managing keys in PKI KRA.

## SYNOPSIS

**pki** [*CLI-options*] **kra-key**  
**pki** [*CLI-options*] **kra-key-find** [*command-options*]  
**pki** [*CLI-options*] **kra-key-show** *key-ID* [*command-options*]  
**pki** [*CLI-options*] **kra-key-request-find** [*command-options*]  
**pki** [*CLI-options*] **kra-key-request-show** *request-ID* [*command-options*]  
**pki** [*CLI-options*] **kra-key-mod** *key-ID* --status *status* [*command-options*]  
**pki** [*CLI-options*] **kra-key-template-find** [*command-options*]  
**pki** [*CLI-options*] **kra-key-template-show** *template-ID* [*command-options*]  
**pki** [*CLI-options*] **kra-key-archive** [*command-options*]  
**pki** [*CLI-options*] **kra-key-retrieve** [*command-options*]  
**pki** [*CLI-options*] **kra-key-generate** *client-key-ID* --key-algorithm *algorithm* [*command-options*]  
**pki** [*CLI-options*] **kra-key-recover** [*command-options*]  
**pki** [*CLI-options*] **kra-key-request-review** *request-ID* --action *action* [*command-options*]  

## DESCRIPTION

The **pki kra-key** commands provide command-line interfaces to manage keys on the KRA.

**pki** [*CLI-options*] **kra-key**  
    This command is to list available key commands.

**pki** [*CLI-options*] **kra-key-find** [*command-options*]  
    This command is to list keys.

**pki** [*CLI-options*] **kra-key-show** *key-ID* [*command-options*]  
    This command is to view the details of a key in the KRA.

**pki** [*CLI-options*] **kra-key-request-find** [*command-options*]  
    This command is to list key requests.

**pki** [*CLI-options*] **kra-key-request-show** *request-ID* [*command-options*]  
    This command is to view the details of a key request submitted to the KRA.

**pki** [*CLI-options*] **kra-key-mod** *key-ID* --status *status* [*command-options*]  
    This command is to modify the status of a particular key in the KRA.

**pki** [*CLI-options*] **kra-key-template-find** [*command-options*]  
    This command is to list the templates for all types of requests in the system.

**pki** [*CLI-options*] **kra-key-template-show** *template-ID* [*command-options*]  
    This command is to view details of the template of a specific key request.

**pki** [*CLI-options*] **kra-key-archive** [*command-options*]  
    This command is to archive a secret in the KRA.

**pki** [*CLI-options*] **kra-key-retrieve** [*command-options*]  
    This command is to retrieve a secret stored in the KRA.

**pki** [*CLI-options*] **kra-key-generate** *client-key-ID* --key-algorithm *algorithm* [*command-options*]  
    This command is to generate a key in the KRA.

**pki** [*CLI-options*] **kra-key-recover** [*command-options*]  
    This command is to recover details of a key in the KRA.

**pki** [*CLI-options*] **kra-key-request-review** --action *action* [*command-options*]  
    This command is to review a key request submitted ot the KRA.

## OPTIONS

The CLI options are described in **pki(1)**.

## OPERATIONS

To view available key commands, type **pki kra-key**.
To view each command's usage, type **pki kra-key-&lt;command&gt; --help**.

All the key commands require agent authentication.

### Viewing the keys

To view the keys stored in KRA:

```
$ pki <agent authentication> kra-key-find
```

To view all active keys for a specific client key ID:

```
$ pki <agent authentication> kra-key-find --clientKeyID <Client Key ID> --status active
```

To view details of a specific key:

```
$ pki <agent authentication> kra-key-show <KeyID>
```

### Archiving a key

To archive a passphrase in the KRA:

```
$ pki <agent authentication> kra-key-archive --clientKeyID <Client Key ID> \
    --passphrase <Passphrase>
```

A symmetric key can be archived using the "archiveKey" request template.

To archive a secret using the request template stored in a file:

```
$ pki <agent authentication> kra-key-archive --input <path to the template file>
```

### Retrieving a key

To retrieve a key using the key ID:

```
$ pki <agent authentication> kra-key-retrieve --keyID <Key Identifier>
```

To retrieve a key using a recovery request template:

```
$ pki <agent authentication> kra-key-retrieve --input <template_file>
```

To retrieve a key encrypted in a custom password:

```
$ pki <agent authentication> kra-key-retrieve --keyID <Key Identifier> --passphrase <passphrase>
```

The returned output contains the secret wrapped in the provided passphrase, using DES3 algorithm,
and the nonce used for encryption.

To store the key information to an output file, use the **--output** option for the command.

### Recovering a key

To initiate a key recovery:

```
$ pki <agent authentication> kra-key-recover --keyID <Key Identifier>
```

The request ID returned by this operation must be approved using the **key-request-review** command
before the actual key retrieval.

To actually recover (retrieve) the PKCS12 of the private key, use the "recovery request template" method listed above under "Retrieving a key"

### Generating a Symmetric Key

To generate a symmetric key using the DES3 algorithm:

```
$ pki <agent authentication> kra-key-generate <Client Key ID> \
    --key-algorithm DES3 --usages wrap,unwrap
```

There are other algorithms to generate symmetric keys such as the AES, DES, DESede, RC2, RC4.

In case of using any of the AES/RC2/RC4 algorithms,
the key size has to be specified using the kra-key-size option of the command.

Generation of asymmetric keys is currently not implemented.

### Reviewing a key request

To approve a key request:

```
$ pki <agent authentication> kra-key-request-review <Request ID> --action approve
```

On successful authentication, the request with the given request ID will be approved.

There other actions that can be performed by an agent are reject/cancel.

### Viewing a request template

To list all the key request templates:

```
$ pki <agent authentication> kra-key-template-find
```

To view a key archival request template:

```
$ pki <agent authentication> kra-key-template-show archiveKey
```

## EXAMPLES

The following pki client examples show the usage of the above operations for a basic CA and KRA server installation.

Only an agent can perform operations on the **key** resource. An agent certificate must be used for authentication.
This can be done by importing an agent certificate into
an NSS database and passing the values to relevant options provided by the pki CLI framework.

Running the following commands will set up the NSS database for use by a pki client and import the agent's certificate
into the database and list information( including the nickname) of the certificate stored in the database.

```
$ certutil -N -d <CERT_DB>
$ pk12util -i <Agent_Cert_P12_FILE> -d <CERT_DB>
$ certutil -L -d <CERT_DB>
```

The first command creates an NSS database. It asks to enter a password for the database.
The second command imports the agent certificate in a PKCS12 format into the database.
It prompts for the passwords of the PKCS12 file and the NSS database.
The third command shows the information about the imported certificate.(including the nickname)

For demonstration purposes, the administrator certificate can be used to perform agent authentication.
In a basic installation setup, the admin cert can be found at /root/.dogtag/pki-tomcat/ca_admin_cert.p12.
Since the installation can only be performed by a root user,
this file must be copied to a location where other users can access it, with valid permissions.

On completion of the setup, and, when issuing the first command using the authentication parameters,
a user may be greeted with a warning message which indicates that an untrusted issuer was encountered.
Simply reply 'Y' to import the CA certificate, and, presuming that the displayed CA server URL is valid,
press the carriage return.

To list all the keys and key requests stored in KRA:

```
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-find
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-request-find
```

To view information of a specific key or a key request stored in KRA:

```
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-show *key-ID*
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-request-show <Request ID>
```

Creating a request for archiving/retrieving/recovering a key

```
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-archive \
    --clientKeyID "vek12345" --passphrase "SampleSecret"
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-retrieve \
    --keyID <Key ID of the archived secret>
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-recover \
    --keyID <Key ID of the archived secret>
```

Generating a symmetric key

```
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-generate \
    "vek123456" --key-algorithm DES3 --usages "encrypt,decrypt"
```

Reviewing a key request

```
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-request-review <Request ID> \
    --action <approve/reject/cancel>
```

## Using templates for creating requests (for advanced users)

The messages for communication between the CLI framework and KRA for accessing the key resource are always encrypted.

In the case of the above mentioned examples,
the encryption and decryption of the secrets is done internally by the PKI client API.

But, applications using the CLI framework to create various requests and also use local encryption,
so the xml templates can be used to supply data to the create a request.

All the templates can be listed by executing:

```
$ pki kra-key-template-find
```

### Creating a kra-key-archival request

To fetch the template for key archival:

```
$ pki kra-key-template-show archiveKey --output <output file>
```

This command gets the template for a key archival request and stores it in an output file.

Following is the description of the various parameters in the key archival template:

- clientKeyID - Unique identifier for the secret.
- dataType - Type of the data to be stored which can be passphrase/symmetricKey/asymmetricKey.
- keyAlgorithm - Algorithm used to create a symmetric key. (Not required if the dataType is passphrase)
- keySize - Size used to generate the symmetric key. (Not required if the dataType is passphrase)
- algorithmOID - Key Algorithm object identifier
- symmetricAlgorithmParams - Base64 encoded nonce data. Nonce used while encrypting the secret.
- wrappedPrivateData - Secret encrypted using a session key(A symmetric key) encoded using Base64.
  This entity contains the secret which is encrypted using a session key.
- transWrappedSessionKey - The session key used to encrypt the secret, wrapped using the KRA transport key,
  and encoded in Base64 format.
- pkiArchiveOptions - An object of type PKIArchiveOptions provided by the NSS/JSS library
  to securely transport a secret encoded in Base64 format.

To create an archival request using the template file:

```
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-archive \
    --input <template_file>
```

### Creating a kra-key-retrieval request

To fetch the template for key retrieval:

```
$ pki kra-key-template-show retrieveKey --output <output file>
```

This command gets the template for a key retrieval request and stores it in an output file.

Following is the description of the various parameters in the key retrieval template:

- keyID - Key identifier
- requestID - Key request identifier
- nonceData - Base64 encoded string of nonce used during encryption (unused for PKCS12 key recovery)
- passphrase - passphrase to encrypt the secret with/ passphrase for the PKCS12 file returned
- sessionWrappedpassphrase - Base64 encoded string of - Passphrase encrypted with a session key. (unused for PKCS12 key recovery)
- transWrapedSessionKey - Base64 encoded string of - session key encrypted with KRA's transport key. (unused for PKCS12 key recovery)
- certificate - Base64 encoded certificate for recovering the key.

To retrieve (recover) keys using the template file (note: key recovery into PKCS12 can only use a template file):

```
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-retrieve \
    --input <template_file>
```

### Creating a symmetric key generation request

To fetch the template for symmetric key generation:

```
$ pki kra-key-template-show generateKey --output <output file>
```

This command gets the template for a symmetric key generation request and stores it in an output file.

Following is the description of the various parameters in the key retrieval template:

- clientKeyID - Client specified unique key identifier
- keyAlgorithm - Algorithm to be used to generate key (AES/DES/DES3/DESede/RC2/RC4)
- keySize - Value for the size of the key to be generated.
- keyUsage - usages of the generated key.
  Useful for Symmetric Keys (DES3,AES,etc) (wrap,unwrap,encrypt,decrypt).
  Useful for Asymmetric Keys (RSA, EC,etc) (wrap,unwrap,encrypt,decrypt,sign,verify,sign_recover,verify_recover).

To create a key generation request using the template file:

```
$ pki -d <CERT_DB> -c <CERT_DB_PWD> -n <Certificate_Nickname> kra-key-generate \
    --input <template_file>
```

## SEE ALSO

**pkispawn(8)**, **pki(1)**

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;, Endi S. Dewata &lt;edewata@redhat.com&gt;,
Matthew Harmsen &lt;mharmsen@redhat.com&gt;, Christina Fu lt;cfu@redhat.com;, and Abhishek Koneru &lt;akoneru@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

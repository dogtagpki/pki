# `PKICertImport`

`PKICertImport` validates and imports certificates

## Overview

The `PKICertImport` utility provides an interface that does validation prior
to importing certificates. This works by wrapping validation (`certutil -V`)
and import (`certutil -A`) in a single script: when certificates fail to
validate, they are removed from the NSS DB. This script supports both
soft tokens and HSMs. When importing a .p12 certificate chain, only soft
tokens are allowed.


## Design Problems

There are a few issues with existing utilities that necessitated a new
wrapper:

 - Existing utilities do not validate certificates prior to importing them.
   This means that certificates could be used prior to their verification.
   We solve this by wrapping everything in a single command, so if validation
   fails, certificates will be removed, minimizing the time they'll be in
   the NSS DB. When importing a `.p12` chain, we also remove added keys.
 - Existing utilities (`pk12util`) do not allow you to set the nicknames of
   all certificates (or even the leaf), so validating (`certutil -V`) is hard.
   We solve this by separating off the leaf certificate and importing it
   separately.
 - Existing utilities (`pk12util`) do not let you set trust on the certificate
   chain on import. We solve this by incrementally validating and trusting
   certificates: if they chain to a trusted root, we'll validate the first
   intermediate certificate and trust it, so any later certificates which chain
   to it can be validated as well.
 - When passwords are required, the user is prompted several times to enter
   the same password. To work around this, password files can be used.
 - Interacting with HSMs can be slow. To work around this, we don't import into
   a separate NSS DB, remove that NSS DB, and re-import to the real NSS DB and
   HSM. Instead, we import directly to the target NSS DB and HSM. This means
   that we're not a true verify-then-import script.


## Structure

The code is structured into the following segments:

1. Definition of global variables.
    - These are parsed from arguments passed to the script and control
      program flow.
2. Definitions of helper functions.
    - Short helper functions.
3. Definitions of core commands.
    - These parse arguments and wrap `certutil`.
4. Program flow section.
    - Calls core commands to parse arguments.

The entire program is wrapped in a function (`PKICertImport`), which is called
at the bottom of the script. This scopes the variables and functions we
define, though might not be strictly necessary.


## Global Variables

In the first section, we define several variables. These fall into three
categories: variables that are always used, variables which are specific
to `.pem` imports, and those specific to `.p12` imports.

Variables which are always used:

 - `CERT_PATH`: the value from the `--certificate` option. This is the path
   to the certificate that we'll pass to `certutil -A`.
 - `CERT_NICKNAME`: the value from the `--nickname` option. This is the
   nickname we'll give the certificate and use to reference the certificate
   for later verification and removal operations. When importing a `.p12`
   chain, this is the nickname of the leaf certificate only.
 - `CERT_TRUST`: the value from the `--trust` option. This is the set of
   trust flags given to `certutil -A` on import. When importing a `.p12`
   chain, this is the trust for the leaf certificate only.
 - `CERT_USAGE`: the value from the `--usage` option. This is the usage
   we'll validate the certificate against. When importing a `.p12` chain,
   this is the usage for the leaf certificate only.
 - `NSSDB`: the value of the `--database` option. This is the destination
   NSS DB we'll add certificates to.
 - `NSSDB_TYPE`: the parsed type to the NSS DB. NSS DBs are either of type
   `dbm:` or `sql:`; we detect this based on the contents of the `NSSDB`
   directory.
 - `NSSDB_PASSWORD`: the value from the `--password` option. This is a file
   which contains the NSS DB and/or HSM passwords.

Used only for importing certificates:

 - `CERT_ASCII`: whether or not the `--ascii` option was given. This means
   that the certificate was in ASCII/PEM format (versus the binary DER format).
 - `HSM_TOKEN`: the value from the `--hsm` option. This is the name of the
   HSM we wish to import the certificate into, if it is specified.

Used only for `.p12` chain imports:

 - `PKCS12_PASSWORD`: the value from the `--pkcs12-password` option. This is
   the file containing the password for the `.p12` chain file, if present.
 - `PKCS12_CHAIN`: whether or not the `--chain` option was given. If present,
   we import the entire chain.
 - `PKCS12_CHAIN_TRUST`: the value from the `--chain-trust` option. These are
   the trust flags applied to intermediate certificates in the chain.
 - `PKCS12_CHAIN_USAGE`: the value from the `--chain-usage` option. These are
   the usage flags the intermediate certificates are validated against.
 - `PKCS12_REMOVE_KEYS`: whether or not the `--unsafe-keep-keys` option was
   given. When specified, we keep all keys imported during `.p12` certificate
   import, even if the corresponding certificates fail to validate.
 - `PKCS12_UNSAFE`: whether or not the `--unsafe-trust-then-verify` option was
   given. When specified, apply trust flags (from `PKCS12_CHAIN_TRUST`) before
   validation. This allows importing the root certificate from a `.p12` chain,
   versus requiring it chain to a known/trusted root.
 - `PKCS12_LEAF`: whether or not the `--leaf-only` option was given. If present,
   we import only the leaf certificate and key from the `.p12` file.

The values for the above variables are parsed in the `_parse_args` function.

The following values for `.p12` certificate chains are filled from other
locations:

 - `PKCS12_CERT_PATH`: path to the leaf certificate when split off from the
   `.p12` chain. Processed in `_split_pkcs12`.
 - `PKCS12_NODES`: nicknames for all intermediate certificates from the
   `.p12` chain import. Processed in `_import_pkcs12`.
 - `PKCS12_KEYS`: nicknames for all keys imported from the `.p12` chain.
   Processed in `_import_pkcs12`.
 - `TMPBASE`: a temporary directory to place stuff in. Processed in
   `__secure_mktmp`.


## Helper Functions

In the second section, we define the following helper functions:

 - `__e`: an error printing helper. Wraps the `echo 1>&2` redirect.
 - `__v`: a verbose logging helper. Conditional around `VERBOSE` being
   specified and non-empty in the calling environment. Used to print `certutil`
   commands before they're run.
 - `__secure_mktmp`: a temporary directory creation helper. Wraps `mktemp` to
   prefer locations backed by memory vs. disk and limit access permissions to
   only the caller of the script. Also copies the file from `CERT_PATH` into
   the new `TMPBASE` and updates `CERT_PATH` to the new location: this ensures
   that when we access `CERT_PATH` multiple times, we get a file we control.
   Otherwise, an attacker could modify the `.p12` as we're reading it to e.g.,
   inject additional certificates.
 - `__secure_rmtmp`: remove the `TMPBASE` directory. If `shred` is present on
   the system, we `shred` the contents before removal.


## Core Commands

In the third section, we define the building blocks of the program. The
following functions are of general usage:

 - `_parse_args`: function which parses the arguments passed to the script.
   Also enforces constraints on the arguments, e.g., `--database` is required.
 - `_print_help`: function which prints the help text and usage information.

The following functions wrap various `certutil` functionality:

 - `_import_cert`: Wrapper for `certutil -A` which handles arguments and
   errors.
 - `_verify_cert`: Wrapper for `certutil -V` which handles arguments and
   errors. The catch here is that `certutil -V`'s return code doesn't
   necessarily show that an error occurred; we have to parse the command's
   output.
 - `_trust_cert`: Wrapper for `certutil -M` which handles arguments and
   ignores errors. We use this for updating the intermediate certificates
   in the chain with their required trust when `--chain` is specified.
 - `_remove_cert`: Wrapper for `certutil -D` which handles arguments and
   errors. Only is called in the event of a failure to validate.
 - `_remove_key`: Wrapper for `certutil -M` which handles arguments and
   errors. Only is called in the event of a failure to validate.

The following functions wrap other utilities for importing `.p12` chains:

 - `_split_pkcs12`: split the leaf certificate from the rest of the `.p12`
   contents. This ensures we can apply the specified nickname to the leaf
   certificate. When `--leaf-only` is specified, we also construct a new `.p12`
   with only the leaf certificate and key.
 - `_import_pkcs12`: import a `.p12` chain using `pk12util`. Before and after
   import, we check the list of certificates and keys in the NSS DB to
   determine which have been added as a result of `p12util`.
 - `_verify_chain`: verify all certificates in the intermediate chain. We keep
   track of which certificates we've validated and which are still waiting
   validation. In the event of failure, we remove certs and keys and exit.
 - `_remove_all_keys`: wrapper for `_remove_key` which removes keys from the
   `.p12` unless `--unsafe-keep-keys` is specified.
 - `_remove_all_certs`: wrapper for `_remove_cert` which removes certs from
   the `.p12`.


## Program Flow

In the last section, we call the above core commands to validate and import
the specified certificates. First, we parse arguments and optionally print
the help text:

 1. Parse the given arguments with `_parse_args`.
 2. If an error occurred during parsing or we were asked to print help:
    - Call `_print_help`.

If we're importing only a single certificate, the process is as follows:

 1. Import the certificate with `_import_cert`.
 2. Validate the certificate with `_verify_cert`.
 3. If validation failed:
    - Remove the certificate with `_remove_cert`.

If we're importing a `.p12` chain, the process is as follows:

 1. Create a secure temporary directory with `__secure_mktmp`.
 2. Split the leaf off of our `.p12` with `_split_pkcs12`.
 3. Import the leaf certificate with `_import_cert`.
 4. Import the `.p12` chain and keys with `_import_pkcs12`.
 5. Verify our chain with `_verify_chain`.
 6. Verify our leaf certificate with `_verify_cert`.
 7. If validation of the leaf failed:
    - Remove all keys with `_remove_all_keys`.
    - Remove all certificates with `_remove_all_certs`.
    - Remove the temporary directory with `__secure_rmtmp`.


## Example Usage

Below are several example use cases for `PKICertImport`.


### Server Certificate

Server certs are validated with `-u V`; trust is assigned automatically when
the private key is present. We don't want to trust it as a CA cert, so trust
flags are empty.

    PKICertImport -d . -n "example.com" -i example-com.crt -t ,, -u V


### CA (Root or Intermediate)

CA certs are validated with `-u L`. Trust needs to be manually assigned; we
give `CT,C,C` to show that it is a trusted CA (`C`), and trusted for client
authentication (`T`).

    PKICertImport -d . -n "MyCA Cert" -i ca-cert.crt -t CT,C,C -u L


### PKCS12 Client Certificate (Leaf Only)

Client certificates are validated with `-u C`. Trust is automatically assigned
when the private keys are present. We also specify `--leaf-only` to import only
the leaf.

    PKICertImport -d . -n "Nick Named" -i nick-named.p12 -t ,, -u C --pkcs12 --leaf-only


### PKCS12 Client Certificate (Chain)

Client certificates are validated with `-u C`. Trust is automatically assigned
when the private keys are present. We also specify `--chain` to import the
the full chain. Intermediate certs are validated with `-u L` and are assigned
full trust once validated (`CT,C,C`). Note that the root CA must be present
already.

    PKICertImport -d . -n "Nick Named" -i nick-named.p12 -t ,, -u C --pkcs12 --chain --chain-trust CT,C,C --chain-usage L


## Test Scenarios

In the following test scenarios, several certificates are used:

  - `Root A`, a trusted root (root of trust).
  - `Sub A.A`, an intermediate signed by `Root A` (trusted).
  - `Server A.B`, signed directly by `Root A` (trusted).
  - `Server A.A.A`, signed by `Sub A.A` (trusted).
  - `Server A.A.B`, signed by `Sub A.A` (trusted).
  - `Root B`, an untrusted root (root of untrust).
  - `Sub B.A`, an intermediate signed by `Root B` (untrusted).
  - `Server B.B`, signed directly by `Root B` (untrusted).
  - `Server B.A.A`, signed by `Sub B.A` (untrusted).
  - `Server B.A.B`, signed by `Sub B.A` (untrusted).

We assume that all signatures are valid unless otherwise noted in the
situations that follow.

### Importing a single certificate

The following scenarios deal with importing certificates from a single `.crt`
file.

#### Successful Import of a Root

Assumptions about NSS DB:

  - It is empty.

Test:

    PKICertImport -d . -n "Root A" -i root-a.crt -t CT,C,C -u L
    PKICertImport -d . -n "Root B" -i root-b.crt -t CT,C,C -u L

Result:

  - Both `Root A` and `Root B` certificates are imported and trusted by the
    NSS DB. Trust is assigned prior to import, so this validates that the
    self-signature on the root is valid.
  - There is no validation we can otherwise perform that would detect the
    difference between `Root A` and `Root B` certificates; we trust that the
    user knows what they're importing.

#### Successful Import of an Intermediate

Assumptions about NSS DB:

  - Contains `Root A`.

Test:

    PKICertImport -d . -n "Sub A.A" -i sub-a.crt -t CT,C,C -u L

Result:

  - The signature on `Sub A.A` is validated to chain to already-trusted `Root A`
    certificate, so `Sub A.A` is successfully imported.

#### Failed Import of an Intermediate

Assumptions about NSS DB:

  - Does not contain `Root A`.
  - Does not contain `Root B`.

Test:

    PKICertImport -d . -n "Sub B.A" -i sub-b.crt -t CT,C,C -u L

Result:

  - Both of these will fail as their signature comes from a certificate
    which is not present in the NSS DB (either `Root A` or `Root B`), and
    so cannot be validated.

#### Successful Import of Server

Assumptions about NSS DB:

  - Contains `Root A`.
  - Contains `Sub A.A`.

Test:

    PKICertImport -d . -n "Server A.B" -i server-a-a.crt -t ,, -u V
    PKICertImport -d . -n "Server A.A.A" -i server-a-b.crt -t ,, -u V
    PKICertImport -d . -n "Server A.A.B" -i server-a-c.crt -t ,, -u V

Result:

  - Server A.B is imported successfully as it has a valid signature by `Root A`.

#### Failed Import of Server (missing intermediate)

Assumptions about NSS DB:

  - Contains `Root A`.

Test:

    PKICertImport -d . -n "Server A.A.A" -i server-a-b.crt -t ,, -u V
    PKICertImport -d . -n "Server A.A.B" -i server-a-c.crt -t ,, -u V
    PKICertImport -d . -n "Server B.B" -i server-b-a.crt -t ,, -u V
    PKICertImport -d . -n "Server B.A.A" -i server-b-b.crt -t ,, -u V
    PKICertImport -d . -n "Server B.A.B" -i server-b-c.crt -t ,, -u V

Result:

  - All of these will fail because the parents of the certificates (either
    `Sub A.A`, `Root B`, or `Sub B.A`) are missing from the NSS DB, and so their
    signatures on these certificates cannot be verified.

### Importing a `.p12` Certificate Chain

In the below, "certificate" is used to mean both "the signed certificate from
a Certificate Authority" and "the private key for said certificate", when the
private key is present in the `.p12` chain.

That is, if a `.p12` chain includes a private key and the corresponding public
key and certificate are successfully verified, the private key will also be
imported into the NSS DB. And, if the corresponding public key and certificate
fail to be verified (invalid signature, trust, etc.), then the private key will
not be present in the NSS DB, unless `--unsafe-keep-keys` is specified.

#### Successful Import of an Entire Chain

Assumptions about NSS DB:

  - Is empty.

Test:

    PKICertImport -d . -n "Server A.A.A" -i server-a-b.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L --unsafe-trust-then-verify

Result:

  - The entire chain of `Root A`, `Sub A.A`, and `Server A.A.A` will be imported
    and trusted by the NSS DB. This includes `Root A`, which introduces a new
    root of trust.
  - This requires that the `.p12` file comes from a trusted source.
  - The server certificate will be named "Server A.A.A" and will be validated as
    a server certificate (`V`), but the intermediate certificates will be
    fully trusted (`CT,C,C`) for both Client and Server certificates, and
    validated as SSL CAs (`L`).

#### Failed Import of Any Part of the Chain

Assumptions about NSS DB:

  - Is empty.

Test:

    PKICertImport -d . -n "Server A.B" -i server-a-a.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L
    PKICertImport -d . -n "Server A.A.A" -i server-a-b.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L
    PKICertImport -d . -n "Server A.A.B" -i server-a-c.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L
    PKICertImport -d . -n "Server B.B" -i server-b-a.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L
    PKICertImport -d . -n "Server B.A.A" -i server-b-b.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L
    PKICertImport -d . -n "Server B.A.B" -i server-b-c.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L

Result:

  - No part of the chain will be trusted or present in the NSS DB. This is
    because root of trust is not present and trusted (`Root A` or `Root B`),
    so during import, neither root of trust can be successfully verified
    (with `certutil -V`). Thus, the entire chain will fail to validate, and
    an error will occur.

#### Successful Import of a Partial Chain

Assumptions about NSS DB:

  - Contains `Root A`.

Test:

    PKICertImport -d . -n "Server A.B" -i server-a-a.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L
    PKICertImport -d . -n "Server A.A.A" -i server-a-b.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L
    PKICertImport -d . -n "Server A.A.B" -i server-a-c.p12 -t ,, -u V --pkcs12 --chain --chain-trust CT,C,C --chain-usage L

Result:

  - The entire chain of `Root A`, `Sub A.A`, and all leaf certificates will be
    imported and trusted by the NSS DB, as `Root A` is already present in the
    NSS DB.
  - In the first step, only the leaf certificate will be imported (as the
    parent certificate, `Root A` is already in the NSS DB).
  - In the second step, both `Sub A.A` and `Server A.A.A` will be imported.
  - In the last step, only` Server A.A.B` will be imported, as `Sub A.A` is
    already present and trusted (from the second step).

#### Successful Import of a Leaf

Assumptions about NSS DB:

  - Contains `Root A`.
  - Contains `Sub A.A`.

Test:

    PKICertImport -d . -n "Server A.B" -i server-a-a.p12 -t ,, -u V --pkcs12 --leaf-only
    PKICertImport -d . -n "Server A.A.A" -i server-a-b.p12 -t ,, -u V --pkcs12 --leaf-only
    PKICertImport -d . -n "Server A.A.B" -i server-a-c.p12 -t ,, -u V --pkcs12 --leaf-only

Result:

  - In the first step, only the leaf certificate will be imported (as the
    parent certificate, `Root A` is already in the NSS DB).
  - In the second step, only` Server A.A.A` will be imported, as `Sub A.A` is
    already present and trusted (from the second step).
  - In the last step, only` Server A.A.B` will be imported, as `Sub A.A` is
    already present and trusted (from the second step).

#### Failed Import of a Leaf

Assumptions about NSS DB:

  - Contains `Root A`.

Test:

    PKICertImport -d . -n "Server A.A.A" -i server-a-b.p12 -t ,, -u V --pkcs12 --leaf-only
    PKICertImport -d . -n "Server A.A.B" -i server-a-c.p12 -t ,, -u V --pkcs12 --leaf-only

Result:

  - Neither certificate will import as their parent (`Sub A.A`) is not trusted in
    the specified NSS DB.

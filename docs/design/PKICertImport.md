# `PKICertImport`

`PKICertImport` validates and imports certificates

## Overview

The `PKICertImport` utility provides an interface that does validation prior
to importing certificates. This works by wrapping validation (`certutil -V`)
and import (`certutil -A`) in a single script: when certificates fail to
validate, they are removed from the NSS DB. This script supports both
soft tokens and HSMs.


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

In the first section, we define the following variables:

 - `CERT_PATH`: the value from the `--certificate` option. This is the path
   to the certificate that we'll pass to `certutil -A`.
 - `CERT_NICKNAME`: the value from the `--nickname` option. This is the
   nickname we'll give the certificate and use to reference the certificate
   for later verification and removal operations.
 - `CERT_ASCII`: whether or not the `--ascii` option was given. This means
   that the certificate was in ASCII/PEM format (versus the binary DER format).
 - `CERT_TRUST`: the value from the `--trust` option. This is the set of
   trust flags given to `certutil -A` on import.
 - `CERT_USAGE`: the value from the `--usage` option. This is the usage
   we'll validate the certificate against.
 - `NSSDB`: the value of the `--database` option. This is the destination
   NSS DB we'll add certificates to.
 - `NSSDB_TYPE`: the parsed type to the NSS DB. NSS DBs are either of type
   `dbm:` or `sql:`; we detect this based on the contents of the `NSSDB`
   directory.
 - `NSSDB_PASSWORD`: the value from the `--password` option. This is a file
   which contains the NSS DB and/or HSM passwords.
 - `HSM_TOKEN`: the value from the `--hsm` option. This is the name of the
   HSM we wish to import the certificate into, if it is specified.

The values for these variables are parsed in the `_parse_args` function.


## Helper Functions

In the second section, we define the following helper functions:

 - `__e`: an error printing helper. Wraps the `echo 1>&2` redirect.
 - `__v`: a verbose logging helper. Conditional around `VERBOSE` being
   specified and non-empty in the calling environment. Used to print `certutil`
   commands before they're run.


## Core Commands

In the third section, we define the building blocks of the program:

 - `_parse_args`: function which parses the arguments passed to the script.
 - `_print_help`: function which prints the help text and usage information.
 - `_import_cert`: Wrapper for `certutil -A` which handles arguments and
   errors.
 - `_verify_cert`: Wrapper for `certutil -V` which handles arguments and
   errors. The catch here is that `certutil -V`'s return code doesn't
   necessarily show that an error occurred; we have to parse the command's
   output.
 - `_remove_cert`: Wrapper for `certutil -D` which handles arguments and
   errors. Only is called in the event of failure.

## Program Flow

In the last section, we call the above core commands to validate and import
the specified certificates.

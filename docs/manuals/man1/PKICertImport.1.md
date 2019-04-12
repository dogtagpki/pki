# PKICertImport 1 "Jan 30, 2019" PKI "PKI certificate import tool"

## NAME

PKICertImport - Used to safely validate and import certificates into the NSS database.

## SYNOPSIS

**PKICertImport** **-d** *NSS-database* **-i** *certificate* **-n** *nickname* **-t** *trust* **-u** *usage* [**-h** *token*] [**-f** *password-file*] [**-a**]

Validate and import a certificate into the specified NSS database.
Verifies signature, trust chain, trust, and usage flags.
If a certificate is not valid, it will not be added to the NSS database or specified token.

## DESCRIPTION

The certificate import utility validates signature, trust chain, trust,
and usage flags before importing a certificate into the specified NSS database.
This ensures that no certificate is used before its authenticity has been verified.
Unlike **certutil**, only one invocation is necessary to both validate and import certificates.

See **certutil** for more information about the parameters to **PKICertImport**.

## OPTIONS

**PKICertImport** parameters:

**--ascii**, **-a**  
    The certificate is encoded in ASCII (PEM) format instead of binary format. Optional.

**--certificate**, **-i** *certificate*  
    Path to the certificate to import. Required.

**--chain**, **-c**  
    Import an entire PKCS12 chain; requires **--pkcs12**. Optional.

**--chain-trust** *trust*  
    Trust flags to assign intermediate certificates; requires **--chain**.

**--chain-usage** *usage*  
    Usage to validate intermediate certificates against; requires **--chain**.

**--database**, **-d** *NSS-database*  
    The directory containing the NSS database. This is usually the client's personal directory. Required.

**--password**, **-f** *password-file*  
    The path to a file containing the password to the NSS database. Optional.

**--hsm**, **-h** *token*  
    Name of the token. If not specified, the default token is the internal database slot. Optional.

**--leaf-only**, **-l**  
    Import only the leaf certificate from a PKCS12 chain; requiers **--pkcs12**. Optional.

**--nickname**, **-n** *nickname*  
    Nickname for the certificate in the NSS database. Required.

**--pkcs12**, **-p**  
    The input certificate is a .p12/PKCS12 file. Optional.

**--pkcs12-password**, **-w** *password-file*  
    Password file for the PKCS12 chain; requires **--pkcs12**.

**--trust**, **-t** *trust*  
    Trust flags for the certificate. See **certutil** for more information about the available trust flags. Required.

**--usage**, **-u** *usage*  
    Usage to validate the certificate against. See **certutil** for more information about available usage flags. Required.

## UNSAFE OPTIONS

**--unsafe-keep-keys**  
    Keep the keys in the NSS DB in the event of a verification failure.

**--unsafe-trust-then-verify**  
    Specify trust when importing the certificate instead of after verifying certificates. This enables importing a new root certificate instead of requiring the chain to have an existing, trusted root.

## ENVIRONMENT

**VERBOSE**  
    When specified, see all internal commands being executed as part of this command.

## EXAMPLES

To import a server certificate:

    PKICertImport -d . -n "example.com" -i example-com.crt -t ,, -u V

To import a CA certificate (root or intermediate):

    PKICertImport -d . -n "MyCA Cert" -i ca-cert.crt -t CT,C,C -u L

To import a leaf client certificate from a PKCS12 chain:

    PKICertImport -d . -n "Nick Named" -i nick-named.p12 -t ,, -u C --pkcs12 --leaf

To import the entire chain of a client certificate:

    PKICertImport -d . -n "Nick Named" -i nick-named.p12 -t ,, -u C --pkcs12 --chain --chain-trust CT,C,C --chain-usage L

## AUTHORS

Alexander Scheel &lt;ascheel@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2019 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

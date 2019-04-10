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

**--database**, **-d** *NSS-database*  
    The directory containing the NSS database. This is usually the client's personal directory. Required.

**--password**, **-f** *password-file*  
    The path to a file containing the password to the NSS database. Optional.

**--hsm**, **-h** *token*  
    Name of the token. By default it takes **internal**. Optional.

**--certificate**, **-i** *certificate*  
    Path to the certificate to import. Required.

**--nickname**, **-n** *nickname*  
    Nickname for the certificate in the NSS database. Required.

**--trust**, **-t** *trust*  
    Trust flags for the certificate. See **certutil** for more information about the available trust flags. Required.

**--usage**, **-u** *usage*  
    Usage to validate the certificate against. See **certutil** for more information about available usage flags. Required.

## AUTHORS

Alexander Scheel &lt;ascheel@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2019 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

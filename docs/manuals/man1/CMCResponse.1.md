# CMCResponse 1 "March 14, 2018" PKI "PKI CMC Response Parsing Tool"

## NAME

CMCResponse - Used to parse CMC responses returned from CMC issuance or revocation requests.

## SYNOPSIS

**CMCResponse** [*OPTIONS*]

## DESCRIPTION

The Certificate Management over Cryptographic Message Syntax (CMC) Response parsing utility, **CMCResponse**,
provides a command-line utility used to parse and present CMC responses from CMC issuance or revocation requests.

It takes the CMC response returned from the CA as input, parses,
and shows the content of the response along with CMC status in a human-readable format.
In addition, it can optionally output the response in PKCS#7 PEM format for further processing by other tools.

## OPTIONS

The following are supported options.

**-d** *path*  
    Path of directory to the NSS database. Defaults to '.' (the current directory).

**-i** *path*  
    Name of file (could include path) for the CMC issuance or revocation response. This option is required.

**-o** *path*  
    Name of file (could include path) to store the certificate chain in PKCS#7 PEM. This is optional.

**-v**  
    If specified, will run in verbose mode, which would entail all certs in the chain being displayed individually in Base64 encoding format.
    It is false by default.

## EXAMPLE

```
$ CMCResponse -d . -i cmc.resp -o cmc.pem
```

## SEE ALSO

**CMCRequest(1)**

## AUTHORS

Christina Fu &lt;cfu@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2018 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

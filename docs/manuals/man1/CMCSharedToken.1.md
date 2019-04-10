# CMCSharedToken 1 "March 14, 2018" PKI "PKI CMC Shared Secret Generation Tool"

## NAME

CMCSharedToken - Used to process a user passphrase and create shared token to be stored by the CA
to allow Shared Secret-based proof of origin in cases such as CMC certificate issuance and revocation.

## SYNOPSIS

**CMCSharedToken** [*OPTIONS*]

## DESCRIPTION

The Certificate Management over Cryptographic Message Syntax (CMC) shared secret generation tool, **CMCSharedToken**,
provides a command-line utility used to process a user passphrase to be shared with the CA.

It takes a passphrase provided by the user, encrypts it with an issuance protection certificate,
and outputs the encrypted blob which could be stored on the CA for subsequent enrollment or revocation activities by the user.

This tool can be run either by the user or by the administrator.
If run by the user, the output (encrypted passphrase, i.e. shared token) needs to be sent to the CA administrator to store on the CA;
if run by the CA administrator, the passphrase itself needs to be passed to the intended user.
It is outside of the scope of this software to state how such communication takes place.
It is up to the site policy to decide which way best suits the deployment site.

For information on how the administrator would store the shared tokens on the CA, see Red Hat Certificate System Administrator's Guide.

## OPTIONS

The following are supported options.

**-d** *database*  
    Path of directory to the NSS database. This option is required.

**-h** *token*  
    Security token name (default: internal)

**-p** *password*  
    Security token password.

**-s** *passphrase*  
    CMC enrollment passphrase (shared secret) (put in "" if containing spaces)

**-b** *issuance-protection-cert*  
    PEM issuance protection certificate. Note: only one of the **-b** or **-n** options should be used.

**-n** *issuance-protection-cert-nickname*  
    PEM issuance protection certificate on token. Note: only one of the **-b** or **-n** options should be used.

**-v**  
    Run in verbose mode.

## EXAMPLE

```
$ CMCSharedToken -d . -p myNSSPassword \
    -s "just another good day" -o cmcSharedTok2.b64 -n "subsystemCert cert-pki-tomcat"
```

## SEE ALSO

**CMCRequest(1)**

## AUTHORS

Christina Fu &lt;cfu@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2018 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

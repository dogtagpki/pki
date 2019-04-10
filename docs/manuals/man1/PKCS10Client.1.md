# PKCS10Client 1 "April 28, 2017" PKI "PKI PKCS10Client certificate request tool"

## NAME

PKCS10Client - Used to generate 1024-bit RSA key pair in the security database.

## SYNOPSIS

**PKCS10Client** **-d** *NSS-database* **-h** *NSS-token* **-p** *NSS-password* **-a** *algorithm* [**-l** *rsa-key-length*] [**-c** *ec-curve-name*] **-o** *output-file* **-n** *subject-DN*

To get a certificate from the CA, the certificate request needs to be submitted to and approved by a CA agent.
Once approved, a certificate is created for the request, and certificate attributes, such as extensions,
are populated according to certificate profiles.

## DESCRIPTION

The PKCS #10 utility, **PKCS10Client**, generates a RSA or EC key pair in the security database,
constructs a PKCS #10 certificate request with the public key, and outputs the request to a file.

**PKCS #10** is a certification request syntax standard defined by RSA.
A CA may support multiple types of certificate requests.
The Certificate System CA supports KEYGEN, PKCS #10, CRMF, and CMC.

## OPTIONS

**PKCS10Client** parameters:

**-d** *NSS-database*  
    The directory containing the NSS database. This is usually the client's personal directory.

**-h** *NSS-token*  
    Name of the token. By default it takes **internal**.

**-p** *NSS-token*  
    The password to the token.

**-a** *algorithm*  
    The algorithm type either **rsa** or **ec**. By default it takes **rsa**.

**-l** *rsa-key-length*  
    The RSA key bit length when **-a** **rsa** is specified. By default it is **1024**.

**-c** *ec-curve-name*  
    Eleptic Curve cryptography curve name.
    Possible values are (if provided by the crypto module):
    nistp256 (secp256r1), nistp384 (secp384r1), nistp521 (secp521r1), nistk163 (sect163k1),
    sect163r1,nistb163 (sect163r2), sect193r1, sect193r2, nistk233 (sect233k1),
    nistb233 (sect233r1), sect239k1, nistk283 (sect283k1), nistb283 (sect283r1),
    nistk409 (sect409k1), nistb409 (sect409r1), nistk571 (sect571k1), nistb571 (sect571r1),
    secp160k1, secp160r1, secp160r2, secp192k1, nistp192 (secp192r1, prime192v1), secp224k1,
    nistp224 (secp224r1), secp256k1, prime192v2, prime192v3, prime239v1, prime239v2,
    prime239v3, c2pnb163v1, c2pnb163v2, c2pnb163v3, c2pnb176v1, c2tnb191v1, c2tnb191v2,
    c2tnb191v3, c2pnb208w1, c2tnb239v1, c2tnb239v2, c2tnb239v3, c2pnb272w1, c2pnb304w1,
    c2tnb359w1, c2pnb368w1, c2tnb431r1, secp112r1, secp112r2, secp128r1, secp128r2,
    sect113r1, sect113r2, sect131r1, sect131r2.

**-o** *output-file*  
    Sets the path and filename to output the new PKCS #10 certificate in base64 format.

**-n** *subject-DN*  
    Gives the subject DN of the certificate.

**-k** *enable-encoding*  
    **true** for enabling encoding of attribute values; **false** for default encoding of attribute values;
    default is **false**.

**-t** *temporary*  
    **true** for temporary(session); **false** for permanent(token); default is **false**.

**-s** *sensitivity*  
    **1** for sensitive; **0** for non-sensitive; **-1** temporaryPairMode dependent; default is **-1**.

**-e** *extractable*  
    **1** for extractable; **0** for non-extractable; **-1** token dependent; default is **-1**.

Also optional for ECC key generation:

**-x** *ecdh-ecdsa*  
    **true** for SSL cert that does ECDH ECDSA; **false** otherwise; default **false**.

**-y** *ski-extension*  
    **true** for adding SubjectKeyIdentifier extension for self-signed CMC shared secret requests;
    **false** otherwise; default **false**.
    To be used with **request.useSharedSecret=true** when running CMCRequest.

## AUTHORS

Amol Kahat &lt;akahat@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2017, 2019 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

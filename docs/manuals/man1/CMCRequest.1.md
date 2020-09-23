# CMCRequest 1 "March 14, 2018" PKI "PKI CMC Request Generation Tool"

## NAME

CMCRequest - Used to generate a CMC certificate issuance or revocation request.

## SYNOPSIS

**CMCRequest** *config-file*

## DESCRIPTION

The Certificate Management over Cryptographic Message Syntax (CMC) Request Generation utility, **CMCRequest**,
provides a command-line utility used to generate a CMC certificate issuance or revocation request.
For issuance request, it requires either a PKCS#10 or CRMF request as input.
The resulting CMC request can be sent to the CA via tool such as **HttpClient**.

**CMCRequest** takes a configuration file where various configuration parameters are supported.

## CONFIGURATION PARAMETERS

The following are supported configuration parameters for the configuration file.
Each parameter is in the format of &lt;name&gt;=&lt;value&gt; (e.g. format=pkcs10).

### numRequests

Total number of PKCS10 or CRMF requests.
(note: lately the CA has only been tested to work with one)

### input

Full path for PKCS #10 or CRMF certificate request in PEM.

For example if **PKCS10Client** or **CRMFPopClient** are used to generate the PKCS#10 or CRMF requests respectively,
this value should be the value of the **-o** option of those command line tools.

### format

Request format. Either **pkcs10** or **crmf**.

### output

Full path for the resulting CMC request in ASN.1 DER encoded format.

Note that this would be the **input** in the **HttpClient** configuration file
if it is used to submit the CMC request.

### dbdir

Directory for NSS database.

### tokenname

Name of crypto token where user signing certificate key can be found (default is internal).

### nickname

The nickname of the user certificate that corresponds to the private key that is used to sign the request.

This parameter is ignored if **useSharedSecret** or **identityProofV2.enable** is true.

### password

Password to the crypto token where the signing user's certificate and keys are stored.

### identification[.enable]

RFC 5272 allows the CA to require inclusion of the **identification** control
to accompany the **identityProofV2** control in a CMC request.

In PKI, CA employs the **identification** control to assist in locating the shared secret
required for verification of the shared secret computed in the **identityProofV2**.

In addition, the **identification** control is also required for **popLinkWitnessV2**
for locating the shared secret.

When **identification.enable** is true, **identification** should contain a user id known by the CA.

### witness.sharedSecret

The **witness.sharedSecret** should contain a passphrase that is known by the CA.
One usually obtains it from the CA administrator.

This parameter is required by the following options: **identityProofV2**, and **popLinkWitnessV2**.

See **CMCSharedToken(1)** for information on usage.

### identityProofV2.[enable, hashAlg, macAlg]

Identity Proof V2 allows one to provide proof of identity without a signing certificate.
It does so by embedding a "witness" value that's calculated from a shared secret (see **witness.sharedSecret**)
known by the CA.

The **identityProofV2** parameter set allows a user to specify the hashing algorithm
as well as MAC (Message Authentication Code) algorithm used to compute the value of the witness value.

Supported **identityProofV2.hashAlg** are: **SHA-256**, **SHA-384**, and **SHA-512**.

Supported **identityProofV2.macAlg** are: **SHA-256-HMAC**, **SHA-384-HMAC**, and **SHA-512-HMAC**.

When **identityProofV2.enable** is true, these parameters must be accompanied by the **identification**
as well as the **witness.sharedSecret** parameters.

These parameters could be accompanied by the **popLinkWitnessV2** parameter set if required by the CA.

### popLinkWitnessV2.[enable, keyGenAlg, macAlg]

The POPLinkWitnessV2 control is a mechanim that links the POP (Proof of Possession) to the identity,
which adds more credibility to the otherwise distinct POP and Proof of Identity mechanisms.
It does so by employing calculation of a random value with a shared secret (see **witness.sharedSecret**)
known by the CA.

The POP Link Witness V2 value must be baked into the PKCS#10 or CRMF requests.
It is therefore crutial that the caller that employs this option has access
to the private key of the certificate request.

If **popLinkWitnessV2** is used, then **identification** and **witness.sharedSecret** must be supplied,
and the **identityProofV2** parameter set is in general used.

Supported keyGenAlg are: **SHA-256**, **SHA-384**, and **SHA-512**.

Supported macAlg are: **SHA-256-HMAC**, **SHA-384-HMAC**, and **SHA-512-HMAC**.

### request.useSharedSecret

**true** or **false**.
If **useSharedSecret** is true, the CMC request will be "signed" with the pairing private key of the enrollment request;
and in which case the **nickname** parameter will be ignored.

**request.useSharedSecret** is only used if a signing certificate (of the agent or user herself)
is not available to sign.
Because the request itself is not signed with a certificate (a proven identity),
the proof of origin (proof of identification) must be provided by some other means.

In PKI, if **request.useSharedSecret** is true,
it must be used in conjunction with the **identityProofV2** and **identification** parameters.
And in that case the Proof Of Origin is accomplished by the Shared Secret (**witness.sharedSecret**) mechanism.

The **request.useSharedSecret** option is normally used to enroll for a user's first signing certificate
while auto-approval (without agent's pre-approval) is preferred.
In general, once a user has obtained the first signing certificate,
such signing certificate can be used to sign (thus proving origin)
and obtain other certificate such as encryption-only ceritifcate,
or when doing a renewal or revocation.

By default, if unspecified, **request.useSharedSecret** is false.

**Note**: to employ the **request.useSharedSecret** option,
the PKCS#10 or CRMF requests must have the **SubjectKeyIdentifier extension**.
(hint: **CRMFPopClient** and **PKCS10Client** should be called with the "-y" option)

If **request.useSharedSecret** is true, **request.privKeyId** must be specified.
It is crucial that the caller that employs this option has access to the private key of the certificate request.

### request.privKeyId

The **request.privKeyId** parameter is required in the following cases:
**request.useSharedSecret**, **popLinkWitnessV2**, and **decryptedPop**

### decryptedPop.enable, encryptedPopResponseFile, decryptedPopRequestFile

In case when the enrolling key is an encryption-only key,
the traditional POP (Proof of Possession) that employs signing of the request is not possible,
CMC provides the EncryptedPOP/DecryptedPOP  mechanism to allow the CA to challenge the client.
This mechanism requires two trips.
First trip (a CMC request without POP) would trigger the CA to generate a challenge
and encrypt the challenge with the request public key in the certificate response
(one should find the EncryptedPOP control as well as status with "failedInfo=POP required" in the CMCResponse);
while second trip from the client would contain proof that the client has decrypted the challenge
and thereby proving ownership of the private key to the enrollment request.
When preparing for the second trip, the following parameters must be present:

**decryptedPop.enable** - set to true; default is false;

**encryptedPopResponseFile** - The input file that contains the CMCResponse from first trip;
It should contains the CMC EncryptedPop control.

**decryptedPopRequestFile** - The output file for the CMC request which should contain the CMC DecryptedPOP control.

**request.privKeyId** - see descripton for **request.privKeyId**;
It is used to decrypt the EncryptedPop, thereby proving the possession of the private key.

Please note that the **PopLinkWitnessV2** control as well as the **request.useSharedSecret** directive
do not apply to EncryptedPOP/DecryptedPOP for the simple fact that
the enrollment private key is not capable of signing.

### revRequest.[enable, serial, reason, comment, issuer, sharedSecret]

Revocation can be done either by signing with user's own valid signing certificate,
or by authenticating with user's shared secret (see **witness.sharedSecret**) known by the CA.

For revocation request signed with user's own valid signing certificate,
the **nickname** parameter should be a valid user signing certificate
that belongs to the same user subject as that of the certificate to be revoked
(but not necessarily the same certificate);
Also, **revRequest.issuer** and **revRequest.sharedSecret** are ignored,
while **revRequest.serial** and **revRequest.reason** must contain valid values.

For revocation by authenticating with user's shared secret, the following parameters are required:
**revRequest.serial**, **revRequest.reason**, **revRequest.issuer**, **revRequest.sharedSecret**,
while **nickname** will be ignored.

**revRequest.reason**  can have one of the following values: **unspecified**, **keyCompromise**, **caCompromise**,
**affiliationChanged**, **superseded**, **cessationOfOperation**, **certificateHold**, **removeFromCRL**.

**revRequest.serial** is in Decimal.

**revRequest.issuer** is issuer subject DN.

**revRequest.invalidityDatePresent** is optional. **true** or **false**.
When true, the invalidityDate of the RevokeRequest will be set to the current time
when this tool is being run.

**revRequest.comment** is optional.

## EXAMPLES

CMC requests must be submitted to the CA to be processed.
Tool supported by PKI for submitting these requests is **HttpClient**.

**Note:** For examples on how to use this tool, please see
[Practical Usage Scenarios](https://www.dogtagpki.org/wiki/PKI_10.4_CMC_Feature_Update_(RFC5272)#Practical_Usage_Scenarios),
and their examples.

## SEE ALSO

**CMCResponse(1)**, **CMCSharedToken(1)**, **CMCRevoke(1)**, **pki(1)**

## AUTHORS

Christina Fu &lt;cfu@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2018 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

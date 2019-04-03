# pki-tps-connector 5 "May 6, 2014" PKI "PKI TPS Profile Configuration"

## NAME

pki-tps-profile - PKI TPS Profile Configuration

## LOCATION

/var/lib/pki/*instance*/conf/tps/CS.cfg

## DESCRIPTION

Token profiles are defined using properties in the TPS configuration file.

### Enrollment Operation For CoolKey

The following property sets the size of the key the token should generate:

```
op.enroll.<tokenType>.keyGen.<keyType>.keySize=1024
```

The maximum value is 1024.

The following properties specify the PKCS11 attributes to set on the token:

```
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.encrypt=false
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.sign=true
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.signRecover=true
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.decrypt=false
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.derive=false
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.unwrap=false
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.wrap=false
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.verifyRecover=true
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.verify=true
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.sensitive=true
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.private=true
op.enroll.<tokenType>.keyGen.<keyType>.keyCapabilities.token=true
```

The following property specifies the CUID shown in the certificate:

```
op.enroll.<tokenType>.keyGen.<keyType>.cuid_label
```

The following property specifies the token name:

```
op.enroll.<tokenType>.keyGen.<keyType>.label
```

The following variables can be used in the token name:

- **$pretty_cuid$** - Pretty Print CUID (i.e. 4090-0062-FF02-0000-0B9C)
- **$cuid$** - CUID (i.e. 40900062FF0200000B9C)
- **$msn$** - MSN
- **$userid$** - User ID
- **$profileId$** - Profile ID

All resulting labels for co-existing keys on the same token must be unique.

The following property determines whether TPS will overwrite key and certificate if they already exist:

```
op.enroll.<tokenType>.keyGen.<keyType>.overwrite=true|false
```

The following properties specify name PKCS11 object IDs:

```
op.enroll.<tokenType>.keyGen.<keyType>.certId=C1
op.enroll.<tokenType>.keyGen.<keyType>.certAttrId=c1
op.enroll.<tokenType>.keyGen.<keyType>.privateKeyAttrId=k2
op.enroll.<tokenType>.keyGen.<keyType>.publicKeyAttrId=k3
op.enroll.<tokenType>.keyGen.<keyType>.privateKeyNumber=2
op.enroll.<tokenType>.keyGen.<keyType>.publicKeyNumber=3
```

Lower case letters signify objects containing PKCS11 object attributes in the format described below:

- **c** - An object containing PKCS11 attributes for a certificate.
- **k** - An object containing PKCS11 attributes for a public or private key
- **r** - An object containing PKCS11 attributes for an "reader".

Upper case letters signify objects containing raw data corresponding to the lower case letters described above.
For example, object **C0** contains raw data corresponding to object **c0**.

- **C** - This object contains an entire DER cert, and nothing else.
- **K** - This object contains a MUSCLE "key blob". TPS does not use this.

The following properties specify the algorithm, the key size, the key usage,
and which PIN user should be granted:

```
op.enroll.<tokenType>.keyGen.<keyType>.alg=2
op.enroll.<tokenType>.keyGen.<keyType>.keySize=1024
op.enroll.<tokenType>.keyGen.<keyType>.keyUsage=0
op.enroll.<tokenType>.keyGen.<keyType>.keyUser=0
```

The valid algorithms are:

- **2** - RSA
- **5** - ECC

For ECC, the valid key sizes are 256 and 384.

Use privilege of the generated private key, or 15 if all users have use privilege for the private key.
Valid usages: (only specifies the usage for the private key)

- **0** - default usage (Signing only for this APDU)
- **1** - signing only
- **2** - decryption only
- **3** - signing and decryption

The following property determines whether to enable writing of PKCS11 cache object to the token:

```
op.enroll.<tokenType>.pkcs11obj.enable=true|false
```

The following property determines whether to enable compression for writing of PKCS11 cache object to the token:

```
op.enroll.<tokenType>.pkcs11obj.compress.enable=true|false
```

The following property determines the maximum number of retries before blocking the token:

```
op.enroll.<tokenType>.pinReset.pin.maxRetries=127
```

The maximum value is 127.

There is a special case of tokenType userKeyTemporary.
Make sure the profile specified by the profileId to have
short validity period (e.g. 7 days) for the certificate.

```
op.enroll.userKey.keyGen.<keyType>.publisherId=fileBasedPublisher
op.enroll.userKeyTemporary.keyGen.<keyType>.publisherId=fileBasedPublisher
```

The folowing property describes the scheme used for recovery:

```
op.enroll.<tokenType>.keyGen.<keyType>.recovery.<tokenState>.scheme=GenerateNewKey
```

The three recovery schemes supported are:

- **GenerateNewKey** - Generate a new cert for the encryption cert.
- **RecoverLast** - Recover the most recent cert for the encryption cert.
- **GenerateNewKeyandRecoverLast** - Generate new cert AND recover last for encryption cert.

### Token Renewal

The following properties are used to define token renewal:

```
op.enroll.<tokenType>.renewal.*
```

For each token in TPS UI, set the following to trigger renewal operations:

```
RENEW=YES
```

Optional grace period enforcement must coincide exactly with what the CA enforces.

In case of renewal, encryption certId values are for completeness only,
server code calculates actual values used.

### Format Operation For tokenKey

The following property determines whether to update applet if the token is empty:

```
op.format.<tokenType>.update.applet.emptyToken.enable=false
```

The property is applicable to:

- CoolKey
- HouseKey
- HouseKey with Legacy Applet

### Certificate Chain Imports

```
op.enroll.certificates.num=1
op.enroll.certificates.value.0=caCert
op.enroll.certificates.caCert.nickName=caCert0 pki-tps
op.enroll.certificates.caCert.certId=C5
op.enroll.certificates.caCert.certAttrId=c5
op.enroll.certificates.caCert.label=caCert Label
```

### Pin Reset Operation For CoolKey

The following property determines whether to update applet if the token is empty:

```
op.pinReset.<tokenType>.update.applet.emptyToken.enable=false
```

The property is not applicable to:

- HouseKey
- HouseKey with Legacy Applet

## SEE ALSO

**pki-tps-profile(1)**

## AUTHORS

Dogtag PKI Team &lt;pki-devel@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2014 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

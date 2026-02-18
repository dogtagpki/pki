# ML-KEM Implementation Guide for Dogtag PKI

This document outlines the required changes to support ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) for post-quantum cryptography in Dogtag PKI.

## Executive Summary

ML-KEM is fundamentally different from ML-DSA because it's a **key encapsulation mechanism** (KEM) rather than a signature algorithm. In Dogtag PKI, this means ML-KEM integration would primarily affect the **KRA (Key Recovery Authority)** subsystem, which handles key archival and recovery operations using key transport/wrapping mechanisms.

## Key Differences: ML-KEM vs ML-DSA

**ML-DSA (Signing):**
- Used for digital signatures (CA operations)
- Affects certificate signing, CRL signing, OCSP signing
- Key usage: `digitalSignature`, `nonRepudiation`, `keyCertSign`, `cRLSign`

**ML-KEM (Key Encapsulation):**
- Used for key transport/wrapping (KRA operations)
- Affects key archival, key recovery, secure key transport
- Key usage: `keyEncipherment`, `dataEncipherment` (NOT `keyAgreement` - that's for ECDH)
- Replaces RSA and EC key transport mechanisms

## Current Key Transport/Wrapping Architecture

### 1. Transport Key Unit

**File**: `base/kra/src/main/java/com/netscape/kra/TransportKeyUnit.java`

**Current Implementation:**
- Uses RSA public key encryption for key transport
- Supports RSA PKCS#1 v1.5 and RSA-OAEP
- Configuration: `keyWrap.useOAEP` setting determines RSA wrapping algorithm
- Algorithm detection based on private key algorithm (lines 330-341, 429-434)

```java
private KeyWrapAlgorithm rsaKeyWrapAlg = KeyWrapAlgorithm.RSA;

boolean useOAEPKeyWrap = kraCfg.getUseOAEPKeyWrap();
if(useOAEPKeyWrap == true) {
    this.rsaKeyWrapAlg = KeyWrapAlgorithm.RSA_OAEP;
}

String priKeyAlgo = wrappingKey.getAlgorithm();
KeyWrapAlgorithm skWrapAlgorithm = null;
if(priKeyAlgo == "RSA") {
    skWrapAlgorithm = rsaKeyWrapAlg;
} else {
    skWrapAlgorithm = params.getSkWrapAlgorithm();
}
```

**Key Methods:**
- `unwrap_sym()` - Unwraps symmetric keys (line 303)
- `decryptExternalPrivate()` - Decrypts private keys from end users (line 318)
- `unwrap_symmetric()` - Unwraps symmetric keys (line 373)
- `unwrap()` - Unwraps private keys (line 413)

### 2. Storage Key Unit

**File**: `base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java`

**Current Implementation:**
- Manages long-term storage keys
- Wraps keys for database storage using storage public key
- Supports wrapping parameters configuration
- Lines 157-160: OAEP support for RSA key wrapping

### 3. Archival Flow

**File**: `base/kra/src/main/java/com/netscape/kra/EnrollmentService.java`

**PKIArchiveOptions Processing:**
- Parses CRMF requests with PKIArchiveOptions
- Extracts encrypted session key and encrypted value
- Supports both ENCRYPTED_VALUE (deprecated) and ENVELOPED_DATA (RFC 4211) formats
- Algorithm OID extracted from archive options

**Key Verification (RSA-specific):**
- Lines 353-382: RSA key pair verification by comparing modulus/exponent
- This is **RSA-specific** and won't work for ML-KEM

### 4. Recovery Flow

**File**: `base/kra/src/main/java/com/netscape/kra/SecurityDataProcessor.java`

**Current Recovery Process:**
- Lines 469-521: Unwraps session key using transport private key
- Lines 526-536: OAEP upgrade logic for RSA
- Lines 604-680: Re-wraps recovered keys with session key for delivery

## Components Requiring Modification for ML-KEM

### 1. NSS/JSS Cryptographic Library Integration

**Current State:**
- Uses `org.mozilla.jss.crypto.KeyWrapAlgorithm` enum
- Supported algorithms: RSA, RSA_OAEP, DES3_CBC_PAD, AES_KEY_WRAP, AES_ECB, etc.

**Required Changes:**
- **Add ML-KEM algorithms to JSS** (upstream dependency)
  - `KeyWrapAlgorithm.ML_KEM_512`
  - `KeyWrapAlgorithm.ML_KEM_768`
  - `KeyWrapAlgorithm.ML_KEM_1024`
- **NSS library support** for ML-KEM encapsulation/decapsulation operations
  - ML-KEM is a KEM, not traditional public key encryption
  - Uses `Encaps(pk) -> (ct, ss)` and `Decaps(sk, ct) -> ss` operations
  - Different from RSA `Encrypt(pk, m)` / `Decrypt(sk, c)` model

**File**: `base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java`
- Need new methods: `mlkemEncapsulate()`, `mlkemDecapsulate()`
- Cannot use existing `wrapUsingPublicKey()` - wrong paradigm

### 2. TransportKeyUnit Modifications

**File**: `base/kra/src/main/java/com/netscape/kra/TransportKeyUnit.java`

**Required Changes:**

```java
// Add ML-KEM algorithm support
private KeyWrapAlgorithm mlkemKeyWrapAlg = KeyWrapAlgorithm.ML_KEM_768; // Default

// Update algorithm detection
String priKeyAlgo = wrappingKey.getAlgorithm();
KeyWrapAlgorithm skWrapAlgorithm = null;
if(priKeyAlgo.equals("RSA")) {
    skWrapAlgorithm = rsaKeyWrapAlg;
} else if(priKeyAlgo.equals("EC")) {
    skWrapAlgorithm = params.getSkWrapAlgorithm();
} else if(priKeyAlgo.equals("ML-KEM")) {  // NEW
    skWrapAlgorithm = mlkemKeyWrapAlg;
}

// New method for ML-KEM decapsulation
public byte[] mlkemDecapsulate(byte[] ciphertext,
                                org.mozilla.jss.crypto.X509Certificate transCert)
    throws Exception {
    CryptoToken token = getToken(transCert);
    PrivateKey mlkemPrivKey = getPrivateKey(transCert);

    // Use NSS/JSS ML-KEM decapsulation
    // Returns shared secret directly (not wrapped with KEM)
    return CryptoUtil.mlkemDecapsulate(token, mlkemPrivKey, ciphertext);
}
```

**Key Differences:**
- ML-KEM produces a **shared secret** directly, not a wrapped key
- Need to derive symmetric key from shared secret (KDF)
- Ciphertext structure different from RSA EncryptedKey

### 3. PKIArchiveOptions / CRMF Integration

**File**: `base/kra/src/main/java/com/netscape/kra/ArchiveOptions.java`

**Current Structure:**
- ENVELOPED_DATA format (preferred, RFC 4211)
- ENCRYPTED_VALUE format (deprecated)
- Extracts: `mSymmAlgOID`, `mSymmAlgParams`, `mEncSymmKey`, `mEncValue`

**ML-KEM Changes:**
- **EnvelopedData with ML-KEM:**
  - RecipientInfo needs ML-KEM variant (likely `KEMRecipientInfo` from CMS)
  - RecipientInfo parsing needs to support KEM ciphertext
  - `encryptedKey` field contains ML-KEM ciphertext (not RSA-wrapped session key)

**New OIDs Required:**
```
id-alg-ml-kem-512  ::= { joint-iso-itu-t(2) country(16) us(840) organization(1)
                         gov(101) csor(3) nistAlgorithm(4) kem(4) ml-kem-512(1) }
id-alg-ml-kem-768  ::= { ... ml-kem-768(2) }
id-alg-ml-kem-1024 ::= { ... ml-kem-1024(3) }
```

### 4. Certificate Profiles for ML-KEM Transport Certificates

**File**: `base/ca/shared/profiles/ca/caTransportCert.cfg`

**Current Constraints:**
- `keyType=RSA`
- `keyParameters=1024,2048,3072,4096` (RSA key sizes)
- Key usage includes `keyEncipherment`, `dataEncipherment`

**ML-KEM Profile:**
```ini
policyset.transportCertSet.3.constraint.params.keyType=ML-KEM
policyset.transportCertSet.3.constraint.params.keyParameters=ML-KEM-512,ML-KEM-768,ML-KEM-1024
# Key usage remains: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
# ML-KEM is used for keyEncipherment (key transport), NOT keyAgreement
```

**Key Usage Notes:**
- `keyEncipherment` - Correct for ML-KEM (key transport)
- `keyAgreement` - **Wrong** for ML-KEM (that's for ECDH/DH)

### 5. Public Key Encoding in Certificates

**File**: `base/kra/src/main/java/com/netscape/kra/EnrollmentService.java`

**Current Public Key Extraction:**
- Line 287-289: `X509Key publicKey = getPublicKey(request, aOpts[i].mReqPos);`
- Line 308: `String keyAlg = publicKey.getAlgorithm();`
- Line 319: `pubkey = X509Key.parsePublicKey(new DerValue(publicKeyData));`

**ML-KEM Public Key Format:**
```
SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm         AlgorithmIdentifier,  -- id-alg-ml-kem-768
    subjectPublicKey  BIT STRING            -- ML-KEM public key bytes
}
```

**Key Sizes:**
- ML-KEM-512: pk=800 bytes, ct=768 bytes
- ML-KEM-768: pk=1184 bytes, ct=1088 bytes
- ML-KEM-1024: pk=1568 bytes, ct=1568 bytes

**Required Changes:**
```java
} else if (keyAlg.equals("ML-KEM")) {
    // Extract ML-KEM parameter set from OID
    String mlkemVariant = extractMLKEMVariant(publicKey.getAlgorithmId());
    MetaInfo metaInfo = new MetaInfo();
    metaInfo.set(KeyRecordParser.OUT_KEY_MLKEM_VARIANT, mlkemVariant);
    rec.set(KeyRecord.ATTR_META_INFO, metaInfo);

    // Set key size based on variant
    if (mlkemVariant.equals("ML-KEM-512")) {
        rec.setKeySize(512);
    } else if (mlkemVariant.equals("ML-KEM-768")) {
        rec.setKeySize(768);
    } else if (mlkemVariant.equals("ML-KEM-1024")) {
        rec.setKeySize(1024);
    }
}
```

### 6. Key Wrapping Flow Modifications

**Two-Layer Wrapping (Current):**
1. Generate random symmetric session key (AES/DES3)
2. Encrypt private key with session key
3. Wrap session key with transport public key (RSA/RSA-OAEP)
4. Store both wrapped session key and encrypted private key

**ML-KEM Flow (Different):**
1. Generate random symmetric session key (AES)
2. Encrypt private key with session key
3. **ML-KEM Encapsulate:** `(ciphertext, shared_secret) = Encaps(transport_pk)`
4. Derive KEK from shared_secret using KDF
5. Wrap session key with KEK
6. Store ML-KEM ciphertext and wrapped session key

**File**: `base/kra/src/main/java/com/netscape/kra/SecurityDataProcessor.java`

**ML-KEM Archival:**
```java
// wrappedSessionKey now contains ML-KEM ciphertext
byte[] sharedSecret = transportUnit.mlkemDecapsulate(
    wrappedSessionKey,  // ML-KEM ciphertext
    transportCert);

// Derive KEK from shared secret
SymmetricKey kek = deriveKEK(sharedSecret, "KRA-Archival-KEK");

// Unwrap session key using KEK
SymmetricKey sessionKey = CryptoUtil.unwrap(
    token,
    SymmetricKey.AES,
    256,
    SymmetricKey.Usage.DECRYPT,
    kek,
    wrappedSessionKeyEncrypted,
    KeyWrapAlgorithm.AES_KEY_WRAP);

// Decrypt private key with session key (unchanged)
byte[] privateKey = CryptoUtil.decryptUsingSymmetricKey(...);
```

### 7. Recovery Flow Modifications

**File**: `base/kra/src/main/java/com/netscape/kra/SecurityDataProcessor.java`

**ML-KEM Recovery:**
```java
// Generate ML-KEM ciphertext and shared secret
byte[] mlkemCiphertext;
byte[] sharedSecret;
(mlkemCiphertext, sharedSecret) = CryptoUtil.mlkemEncapsulate(
    token,
    transportCert.getPublicKey());

// Derive KEK from shared secret
SymmetricKey kek = deriveKEK(sharedSecret, "KRA-Recovery-KEK");

// Wrap session key with KEK
byte[] wrappedSessionKey = CryptoUtil.wrapUsingSymmetricKey(
    token,
    kek,
    recoveredSessionKey,
    null,
    KeyWrapAlgorithm.AES_KEY_WRAP);

// Return ML-KEM ciphertext and wrapped session key
params.put(Request.SECURITY_DATA_MLKEM_CIPHERTEXT, Utils.base64encode(mlkemCiphertext));
params.put(Request.SECURITY_DATA_SESS_WRAPPED_DATA, Utils.base64encode(wrappedSessionKey));
```

### 8. Configuration Changes

**File**: `base/kra/shared/conf/CS.cfg`

**New Configuration Parameters:**
```ini
# ML-KEM Support
kra.transport.mlkem.enable=true
kra.transport.mlkem.variant=ML-KEM-768
kra.storage.mlkem.enable=true
kra.storage.mlkem.variant=ML-KEM-768

# Key wrapping algorithm selection
keyWrap.algorithm=ML-KEM  # or RSA, RSA-OAEP
```

## Critical Differences from Traditional Public Key Encryption

### RSA Key Transport
```
1. Generate session key (SK)
2. Encrypt data with SK
3. ct = RSA_Encrypt(transport_pk, SK)
4. Store (ct, encrypted_data)

Recovery:
1. SK = RSA_Decrypt(transport_sk, ct)
2. data = Decrypt(SK, encrypted_data)
```

### ML-KEM Key Transport
```
1. Generate session key (SK)
2. Encrypt data with SK
3. (ct, ss) = ML_KEM_Encapsulate(transport_pk)
4. KEK = KDF(ss, context)
5. wrapped_SK = AES_KeyWrap(KEK, SK)
6. Store (ct, wrapped_SK, encrypted_data)

Recovery:
1. ss = ML_KEM_Decapsulate(transport_sk, ct)
2. KEK = KDF(ss, context)
3. SK = AES_KeyUnwrap(KEK, wrapped_SK)
4. data = Decrypt(SK, encrypted_data)
```

**Key Insight:** ML-KEM doesn't directly encrypt the session key. It generates a shared secret that must be processed through a KDF to derive a key-encrypting key (KEK). This is fundamentally different from RSA's direct encryption paradigm.

## Key Architectural Differences from ML-DSA Implementation

| Aspect | ML-DSA (Signatures) | ML-KEM (Key Transport) |
|--------|---------------------|------------------------|
| **Primary Component** | CA (Certificate Authority) | KRA (Key Recovery Authority) |
| **Operation** | Sign/Verify | Encapsulate/Decapsulate |
| **Use Case** | Certificate signing, CRL signing, OCSP | Key archival, key recovery |
| **Key Usage** | digitalSignature, keyCertSign, cRLSign | keyEncipherment, dataEncipherment |
| **Cryptographic Primitive** | Digital signature scheme | Key encapsulation mechanism |
| **Session Key Handling** | N/A | Derives symmetric key from shared secret |
| **Certificate Profile** | Signing certificates (CA cert, audit log signing) | Transport certificates (KRA transport cert) |
| **Backward Compatibility** | Hybrid signatures possible | Hybrid encryption needed for transition |
| **Standards** | FIPS 204 | FIPS 203 |

## Implementation Roadmap

### Phase 1: NSS/JSS Foundation (Upstream Dependencies)

1. **Add ML-KEM support to NSS library**
   - Implement `ML_KEM_Encapsulate()` and `ML_KEM_Decapsulate()` functions
   - Support ML-KEM-512, ML-KEM-768, ML-KEM-1024 parameter sets
   - Add OID definitions per NIST FIPS 203

2. **Update JSS (Java Security Services)**
   - Add `KeyWrapAlgorithm.ML_KEM_512/768/1024` enum values
   - Implement `CryptoUtil.mlkemEncapsulate()` and `mlkemDecapsulate()` methods
   - Add ML-KEM key pair generation support
   - Update `SubjectPublicKeyInfo` parsing for ML-KEM public keys

3. **Add KDF support for shared secret derivation**
   - HKDF or SP 800-108 KDF
   - Derive KEK from ML-KEM shared secret

### Phase 2: Core KRA Modifications

1. **TransportKeyUnit** (`base/kra/src/main/java/com/netscape/kra/TransportKeyUnit.java`)
   - Add `mlkemKeyWrapAlg` configuration
   - Implement `mlkemDecapsulate()` method
   - Update algorithm detection logic (lines 330-341, 429-434)
   - Add shared secret → KEK derivation

2. **StorageKeyUnit** (`base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java`)
   - Update wrapping params to support ML-KEM
   - Modify `getWrappingParams()` to include ML-KEM options
   - Update `wrap()` and `unwrap()` methods

3. **EncryptionUnit** (`base/kra/src/main/java/com/netscape/kra/EncryptionUnit.java`)
   - Add ML-KEM algorithm handling
   - Update `unwrap_session_key()` for ML-KEM shared secrets

### Phase 3: PKIArchiveOptions / CRMF Support

1. **ArchiveOptions** (`base/kra/src/main/java/com/netscape/kra/ArchiveOptions.java`)
   - Support KEMRecipientInfo in EnvelopedData
   - Parse ML-KEM ciphertext from RecipientInfo
   - Handle ML-KEM algorithm OIDs

2. **EnrollmentService** (`base/kra/src/main/java/com/netscape/kra/EnrollmentService.java`)
   - Update public key extraction for ML-KEM
   - Add ML-KEM key size handling
   - Modify archival flow for ML-KEM decapsulation
   - Update key verification (current code is RSA-specific)

3. **SecurityDataProcessor** (`base/kra/src/main/java/com/netscape/kra/SecurityDataProcessor.java`)
   - Modify archival flow
   - Update recovery flow
   - Add ML-KEM ciphertext generation for recovery
   - Implement shared secret → KEK derivation

### Phase 4: Certificate Profiles

1. **Create ML-KEM transport certificate profile**
   - `caMLKEMTransportCert.cfg`
   - Key type: ML-KEM
   - Key parameters: ML-KEM-512, ML-KEM-768, ML-KEM-1024
   - Key usage: keyEncipherment, dataEncipherment (NOT keyAgreement)

2. **Create ML-KEM storage certificate profile**
   - `caMLKEMStorageCert.cfg`
   - Similar structure to transport cert

3. **Update existing profiles**
   - Add ML-KEM to allowed key types where appropriate

### Phase 5: Configuration & Deployment

1. **Add configuration parameters to `CS.cfg`**
   - `kra.transport.mlkem.enable`
   - `kra.transport.mlkem.variant`
   - `kra.storage.mlkem.enable`
   - `keyWrap.algorithm`

2. **Update deployment scripts (`pkispawn`)**
   - Generate ML-KEM transport key pairs
   - Support hybrid RSA+ML-KEM deployment

3. **Add migration tools**
   - Re-wrap existing keys with ML-KEM transport certs
   - Support dual RSA/ML-KEM transport certs during transition

### Phase 6: Testing

1. **Unit tests for ML-KEM operations**
   - Encapsulate/Decapsulate
   - Shared secret derivation
   - Key wrapping/unwrapping

2. **Integration tests**
   - End-to-end archival with ML-KEM
   - End-to-end recovery with ML-KEM
   - Hybrid RSA+ML-KEM scenarios

3. **Performance testing**
   - ML-KEM is faster than RSA for key transport
   - Benchmark archival/recovery operations

## Critical Files Summary

### Files Requiring Modification

**KRA Core:**
- `base/kra/src/main/java/com/netscape/kra/TransportKeyUnit.java`
- `base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java`
- `base/kra/src/main/java/com/netscape/kra/EncryptionUnit.java`
- `base/kra/src/main/java/com/netscape/kra/EnrollmentService.java`
- `base/kra/src/main/java/com/netscape/kra/SecurityDataProcessor.java`
- `base/kra/src/main/java/com/netscape/kra/RecoveryService.java`

**CRMF/PKIArchiveOptions:**
- `base/kra/src/main/java/com/netscape/kra/ArchiveOptions.java`
- `base/server/src/main/java/com/netscape/cmscore/crmf/PKIArchiveOptionsContainer.java`

**Crypto Utilities:**
- `base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java`

**Certificate Profiles:**
- `base/ca/shared/profiles/ca/caTransportCert.cfg`
- `base/ca/shared/profiles/ca/caStorageCert.cfg`
- `base/server/certs/kra_transport.conf`
- `base/server/certs/kra_storage.conf`

**Configuration:**
- `base/kra/shared/conf/CS.cfg`
- `base/server/etc/default.cfg`

## Migration & Hybrid Support

### Transition Strategy

1. **Deploy ML-KEM transport certificates** alongside existing RSA transport certs
2. **Clients choose algorithm** via PKIArchiveOptions
3. **KRA accepts both** RSA and ML-KEM wrapped keys
4. **Gradual migration** as clients adopt ML-KEM
5. **Legacy support** maintained for existing archived keys

### Hybrid Encryption

- CMS (RFC 5652) supports multiple RecipientInfo entries
- Can wrap session key with both RSA and ML-KEM simultaneously
- Ensures backward compatibility during transition

## Recommendations

1. **Upstream First**: ML-KEM support MUST be added to NSS and JSS before Dogtag changes
2. **KDF Standardization**: Establish standard KDF for deriving KEK from ML-KEM shared secret
3. **Hybrid Mode**: Support dual RSA+ML-KEM transport during transition period
4. **Testing Strategy**: Focus on archival/recovery workflows as critical path
5. **Performance**: ML-KEM operations are faster than RSA - expect performance improvements
6. **OID Management**: Ensure JSS properly encodes ML-KEM OIDs per NIST FIPS 203
7. **Documentation**: Update KRA documentation to explain ML-KEM key transport mechanism

## Conclusion

ML-KEM support requires **significant KRA subsystem changes** compared to ML-DSA's minimal CA modifications. The fundamental difference between key encapsulation (ML-KEM) and digital signatures (ML-DSA) means the integration points are entirely different. The key challenge is adapting the two-layer wrapping architecture (session key + transport key) to work with ML-KEM's shared secret paradigm, which requires KDF support for deriving KEKs.

The heavy lifting remains in **NSS/JSS** for the cryptographic primitives, but Dogtag's KRA subsystem will require substantial code modifications to support the new key transport mechanism.

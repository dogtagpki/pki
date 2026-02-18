# ML-DSA Implementation Guide for Dogtag PKI

This document outlines the required changes to support ML-DSA (Module-Lattice-Based Digital Signature Algorithm) for post-quantum cryptography certificate issuance in Dogtag PKI.

## Critical Dependencies (Must be completed first)

### 1. NSS Library (upstream)
- Implement ML-DSA-44, ML-DSA-65, and ML-DSA-87 algorithms per NIST FIPS 204
- Register OIDs:
  - ML-DSA-44: `2.16.840.1.101.3.4.3.17`
  - ML-DSA-65: `2.16.840.1.101.3.4.3.18`
  - ML-DSA-87: `2.16.840.1.101.3.4.3.19`
- Add signature/verification operations and key generation

### 2. JSS Library (Mozilla upstream)
- Add ML-DSA `SignatureAlgorithm` enum values
- Update `AlgorithmId.ALL_SIGNING_ALGORITHMS` array
- Modify `AlgorithmId.getSigningAlgorithms()` to map ML-DSA public keys to compatible signature algorithms
- Update `Cert.mapAlgorithmToJss()` to recognize ML-DSA algorithm strings
- Create `AlgorithmId` objects with proper OID encoding

## Dogtag PKI Changes (after JSS/NSS support)

### 3. Code Changes (minimal)

**File**: `base/ca/src/main/java/com/netscape/cms/profile/def/SigningAlgDefault.java:50`
```java
public static final String DEF_CONFIG_ALGORITHMS =
    "-,SHA256withRSA,SHA384withRSA,SHA512withRSA,ML-DSA-44,ML-DSA-65,ML-DSA-87";
```

### 4. Configuration Changes

Update all certificate profile files in `base/ca/shared/profiles/ca/*.cfg`:
```ini
policyset.userCertSet.9.constraint.params.signingAlgsAllowed=SHA256withRSA,SHA512withRSA,SHA256withEC,ML-DSA-44,ML-DSA-65,ML-DSA-87
```

## Architecture Analysis

### Why So Few Dogtag Changes?

The architecture is **designed for algorithm extensibility**:

1. **Dynamic Algorithm Discovery**: `CertificateAuthority.java:688-720` dynamically queries JSS for available algorithms based on the CA's public key type
2. **Delegated Signing**: `CASigningUnit.java:156-195` delegates all cryptographic operations to JSS/NSS
3. **String-to-Algorithm Mapping**: `Cert.mapAlgorithmToJss()` (in JSS) handles algorithm name resolution

Once JSS recognizes ML-DSA algorithms, they automatically become available through `AlgorithmId.getSigningAlgorithms()` - Dogtag just needs configuration updates to expose them in profiles.

### Key Code Flow

#### Certificate Signing Workflow (`CertificateAuthority.java:562-609`)
```java
public X509CertImpl sign(X509CertInfo certInfo, String algname) throws Exception {
    if (algname == null) {
        algname = mSigningUnit.getDefaultAlgorithm();
    }

    // 1. Get AlgorithmId from JSS
    AlgorithmId alg = AlgorithmId.get(algname);

    // 2. Encode certificate info to bytes
    certInfo.encode(tmp);
    byte[] rawCert = tmp.toByteArray();

    // 3. Encode algorithm identifier
    alg.encode(tmp);

    // 4. Sign using JSS/NSS via signing unit
    byte[] signature = mSigningUnit.sign(rawCert, algname);

    // 5. Construct final certificate
    tmp.putBitString(signature);
    out.write(DerValue.tag_Sequence, tmp);
    signedcert = new X509CertImpl(out.toByteArray());
}
```

#### Actual Signing Operation (`CASigningUnit.java:156-195`)
```java
public byte[] sign(byte[] data, String algname) throws Exception {
    SignatureAlgorithm signAlg = mDefSigningAlgorithm;

    if (algname != null) {
        signAlg = checkSigningAlgorithmFromName(algname);
    }

    // Get JSS signature context from crypto token (NSS)
    Signature signer = mToken.getSignatureContext(signAlg);
    signer.initSign(mPrivk);
    signer.update(data);
    return signer.sign();  // Actual signing happens in NSS
}
```

## Implementation Roadmap

### Phase 1: Foundation (NSS/JSS Updates)
1. **NSS Library** (upstream dependency):
   - Add ML-DSA algorithm implementation (ML-DSA-44, ML-DSA-65, ML-DSA-87)
   - Register OIDs per NIST FIPS 204 specification
   - Implement signature and verification operations
   - Add key generation support

2. **JSS Library** (Mozilla upstream):
   - Add `SignatureAlgorithm` enum entries for ML-DSA variants
   - Update `AlgorithmId.ALL_SIGNING_ALGORITHMS` array
   - Implement `AlgorithmId.getSigningAlgorithms()` mapping for ML-DSA public keys
   - Update `Cert.mapAlgorithmToJss()` to recognize ML-DSA algorithm strings
   - Add ML-DSA `AlgorithmId` objects with proper OID encoding

### Phase 2: Dogtag PKI Configuration

3. **Algorithm Name Standards**:
   - Establish naming convention (e.g., "ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
   - Ensure consistency across all configuration files

4. **Profile Defaults** (minimal code changes):
   - Update `SigningAlgDefault.java:50` with ML-DSA algorithm names

5. **Certificate Profiles** (configuration only):
   - Update all relevant profile `.cfg` files in `base/ca/shared/profiles/ca/`
   - Add ML-DSA variants to `signingAlgsAllowed` parameters

### Phase 3: Testing and Validation

6. **Integration Testing**:
   - Generate ML-DSA key pairs in NSS database
   - Create CA with ML-DSA signing key
   - Test certificate issuance with ML-DSA signatures
   - Verify signature validation works correctly
   - Test profile constraints properly accept/reject ML-DSA

7. **Compatibility Testing**:
   - Ensure existing RSA/EC operations unaffected
   - Test hybrid CA deployments (traditional + PQC)
   - Validate OCSP signing with ML-DSA
   - Test CRL signing with ML-DSA

## Existing Patterns for Adding New Algorithms

### RSA-PSS Addition Pattern
Recent addition of RSA-PSS variants demonstrates the pattern:
- Added to JSS `AlgorithmId.ALL_SIGNING_ALGORITHMS`
- Included in profile configurations: "SHA256withRSA/PSS", "SHA384withRSA/PSS", "SHA512withRSA/PSS"
- No Dogtag core code changes needed beyond configuration updates

### EC Algorithm Support
Elliptic curve support shows similar pattern:
- EC algorithms defined in JSS (`SHA256withEC`, `SHA384withEC`, `SHA512withEC`)
- Dynamic algorithm discovery via `AlgorithmId.getSigningAlgorithms()` based on key type
- Profile configurations updated to include EC variants

### Key Insight
**The architecture is designed for algorithm extensibility**. Once JSS/NSS support an algorithm:
1. It automatically becomes available via `AlgorithmId.getSigningAlgorithms()`
2. Only configuration files need updates to expose it in profiles
3. Minimal to no Java code changes required in Dogtag itself

## Critical Files Summary

### Files Defining Algorithm Support (External Dependencies):
1. **JSS Library**: `org.mozilla.jss.netscape.security.x509.AlgorithmId`
2. **JSS Library**: `org.mozilla.jss.netscape.security.util.Cert.mapAlgorithmToJss()`
3. **NSS Library**: Actual cryptographic implementation

### Files Requiring ML-DSA Configuration Updates:
1. `base/ca/src/main/java/com/netscape/cms/profile/def/SigningAlgDefault.java` - Default algorithm list
2. `base/ca/shared/profiles/ca/*.cfg` - All certificate profile configurations
3. Potentially `base/ca/src/main/java/org/dogtagpki/legacy/server/policy/constraints/SigningAlgorithmConstraints.java` - Legacy policy (if used)

### Files with Algorithm-Aware Logic (No changes needed):
1. `base/ca/src/main/java/com/netscape/ca/CertificateAuthority.java` - Algorithm discovery
2. `base/ca/src/main/java/com/netscape/ca/CASigningUnit.java` - Signing operations
3. `base/server/src/main/java/com/netscape/certsrv/security/SigningUnit.java` - Base signing logic
4. `base/ca/src/main/java/com/netscape/cms/profile/constraint/SigningAlgConstraint.java` - Constraint validation

## Testing Requirements

1. Generate ML-DSA key pairs in NSS database
2. Create CA with ML-DSA signing certificate
3. Issue certificates using ML-DSA signatures
4. Verify OCSP and CRL signing with ML-DSA
5. Test profile constraints properly validate ML-DSA requests
6. Ensure backward compatibility with existing RSA/EC certificates

## Recommendations

1. **Upstream First**: ML-DSA support MUST be added to NSS and JSS before Dogtag changes
2. **Minimal Dogtag Changes**: Design suggests only configuration updates needed, minimal code
3. **Naming Convention**: Establish standard ML-DSA algorithm naming early (coordinate with JSS team)
4. **Testing Strategy**: Focus on JSS/NSS integration testing as the critical path
5. **Backward Compatibility**: Existing algorithm support should remain unaffected
6. **OID Management**: Ensure JSS properly encodes ML-DSA OIDs per NIST FIPS 204
7. **Documentation**: Update profile documentation to indicate ML-DSA as post-quantum option

## Conclusion

The heavy lifting for ML-DSA support is in **NSS/JSS** - Dogtag changes are primarily **configuration-based** with minimal code modifications. The architecture's design for algorithm extensibility means that once the cryptographic libraries support ML-DSA, Dogtag can leverage it with relatively small changes focused on exposing the new algorithms through certificate profiles.

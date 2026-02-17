# Building the EST Quarkus PoC

## Overview

This Proof of Concept demonstrates the architectural patterns for migrating Dogtag PKI from Tomcat to Quarkus. It references classes from the existing PKI codebase to show real migration patterns.

## Build Requirements

### Option 1: Build with Parent PKI (Recommended for Development)

To build this PoC with actual PKI functionality:

1. **Install JSS and LDAP SDK dependencies first**
   ```bash
   # Install from COPR repository
   sudo dnf copr -y enable @pki/master
   sudo dnf install -y jss ldapjdk
   ```

2. **Build parent PKI modules**
   ```bash
   cd /path/to/pki
   ./build.sh dist
   ```

   This will build and install PKI artifacts to your local Maven repository (`~/.m2/repository`).

3. **Build the Quarkus PoC**
   ```bash
   cd base/est-quarkus
   mvn clean package
   ```

### Option 2: Standalone Demo Build (For Quick Review)

For reviewers who want to understand the migration patterns without building the full PKI stack:

1. **Review the source code directly**
   - The Java classes in `src/main/java/org/dogtagpki/est/quarkus/` demonstrate the migration patterns
   - Compare with original Tomcat versions in `../est/src/main/java/org/dogtagpki/est/`
   - Read `README.md` and `MIGRATION-GUIDE.md` for architecture details

2. **Key files to review**:
   - `ESTEngineQuarkus.java` - CDI lifecycle vs ServletContextListener
   - `ESTFrontendQuarkus.java` - JAX-RS migration (javax → jakarta)
   - `ESTCertificateAuthenticationMechanism.java` - Quarkus security vs Tomcat Realm
   - `application.yaml` - Config migration from web.xml
   - `pom.xml` - Quarkus dependencies vs Tomcat

## Why Does This PoC Depend on Parent PKI?

The PoC intentionally reuses existing PKI classes to demonstrate:

1. **Real Migration** - Shows actual code migration, not toy examples
2. **Backend Reuse** - Demonstrates that Quarkus frontend can use existing backend logic
3. **Hybrid Approach** - Validates that Tomcat-based backends can work with Quarkus presentation layer

### Classes Referenced from Parent PKI

From `org.dogtagpki.est` (original EST subsystem):
- `ESTBackend` - Certificate enrollment backend interface
- `ESTBackendConfig` - Backend configuration
- `ESTRequestAuthorizer` - Authorization logic
- `ESTRequestAuthorizerConfig` - Authorizer configuration
- `ESTRequestAuthorizationData` - Authorization data structure

From `com.netscape.certsrv.base` (PKI common):
- `PKIException`, `BadRequestException`, `ForbiddenException`, etc.

From Mozilla JSS:
- `PKCS10` - Certificate signing request
- `X509CertImpl` - X.509 certificate implementation
- `CertificateChain` - Certificate chain encoding

## Build Without Parent PKI (Future Enhancement)

To make this PoC fully standalone, we could:

1. **Create stub implementations** of PKI classes
2. **Use standard Java security APIs** instead of JSS where possible
3. **Mock the backend** for demonstration purposes

However, this would hide the real migration complexity and make the PoC less valuable for actual migration planning.

## Recommended Workflow

For evaluating this PoC:

1. **Architecture Review** - Read the documentation and source code
2. **Build Parent PKI** - Follow the main PKI build instructions
3. **Build and Test PoC** - Compile and run the Quarkus version
4. **Compare Implementations** - Side-by-side comparison of Tomcat vs Quarkus

## Running the PoC

Once built:

```bash
# Development mode with live reload
mvn quarkus:dev

# Production mode
java -jar target/quarkus-app/quarkus-run.jar

# Native compilation (requires GraalVM)
mvn package -Pnative
./target/pki-est-quarkus-11.6.0-SNAPSHOT-runner
```

## Troubleshooting

### "Could not resolve dependencies" Error

**Symptom:**
```
[ERROR] Could not find artifact org.dogtagpki.pki:pki-est:jar:11.6.0-SNAPSHOT
```

**Solution:**
Build the parent PKI project first (see Option 1 above).

### "No versions available for org.dogtagpki.jss:jss-base"

**Symptom:**
```
[ERROR] No versions available for org.dogtagpki.jss:jss-base:jar:[5.5.0-SNAPSHOT,)
```

**Solution:**
Install JSS from COPR or build from source:
```bash
sudo dnf copr enable @pki/master
sudo dnf install jss
```

## For More Information

- Main PKI Build Guide: `../../docs/development/Building_PKI.md`
- PoC Architecture: `README.md`
- Migration Patterns: `MIGRATION-GUIDE.md`
- PKI Project: https://github.com/dogtagpki/pki

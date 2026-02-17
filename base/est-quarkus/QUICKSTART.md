# EST Quarkus PoC - Quick Start Guide

## Understanding the PoC

This Proof of Concept demonstrates **architectural migration patterns** from Tomcat to Quarkus by migrating the real EST subsystem. It intentionally references existing PKI classes to show how actual migration would work, rather than creating a toy example.

## Three Ways to Use This PoC

### Option 1: Podman Development Environment (Recommended) ⭐

**Best for:** Hands-on building and testing without installing dependencies

**Time:** 15-20 minutes

**Steps:**
```bash
cd base/est-quarkus

# Build container with all dependencies
./podman-build.sh

# Run development environment
./podman-run.sh

# Inside container: build and run
./quarkus-dev.sh
```

See **[PODMAN.md](PODMAN.md)** for complete guide.

**What you get:**
- ✅ Zero host dependencies (just Podman)
- ✅ Complete build environment (Java, Maven, JSS, LDAP SDK)
- ✅ Live reload development
- ✅ Clean, isolated environment

### Option 2: Review the Architecture (5 minutes)

**Best for:** Understanding migration patterns without building

**Steps:**
1. Read [README.md](README.md) - Architecture overview
2. Read [MIGRATION-GUIDE.md](MIGRATION-GUIDE.md) - Step-by-step migration patterns
3. Review source code:
   - `src/main/java/org/dogtagpki/est/quarkus/ESTEngineQuarkus.java` - Lifecycle migration
   - `src/main/java/org/dogtagpki/est/quarkus/ESTFrontendQuarkus.java` - REST endpoint migration
   - `src/main/java/org/dogtagpki/est/quarkus/ESTCertificateAuthenticationMechanism.java` - Authentication
   - `src/main/resources/application.yaml` - Configuration
4. Compare with original Tomcat code in `../est/src/main/java/`

**What you'll learn:**
- CDI lifecycle events vs ServletContextListener
- Jakarta EE vs javax namespaces
- Quarkus Security vs Tomcat Realms
- MicroProfile Config vs properties files
- Security constraints in YAML vs web.xml

### Option 3: Native Build and Run (30-60 minutes)

**Best for:** Building directly on your host system

**Prerequisites:**
- Java 17+
- Maven 3.8+
- Fedora/RHEL (for JSS/LDAP SDK)

**Steps:**

#### Step 1: Install JSS and LDAP SDK
```bash
# On Fedora/RHEL
sudo dnf copr enable @pki/master
sudo dnf install -y jss ldapjdk

# On other systems, use Docker
docker run -it fedora:latest
dnf install -y jss ldapjdk maven java-17-openjdk-devel
```

#### Step 2: Build Parent PKI
```bash
cd /path/to/pki
./build.sh dist
```

This builds and installs PKI artifacts to `~/.m2/repository`.

#### Step 3: Build Quarkus PoC
```bash
cd base/est-quarkus
mvn clean package
```

#### Step 4: Run the PoC
```bash
# Development mode (with live reload)
mvn quarkus:dev

# Access:
# - Dev UI: http://localhost:8080/q/dev
# - Health: http://localhost:8080/q/health
# - Metrics: http://localhost:8080/q/metrics
# - EST API: https://localhost:8443/rest/cacerts
```

## Why Does Build Require Parent PKI?

The PoC demonstrates **real migration**, not a simplified example. It shows:

1. **Backend Reuse** - Existing `ESTBackend` implementations work with Quarkus frontend
2. **Incremental Migration** - You can migrate presentation layer first, keep backend on Tomcat libraries
3. **Actual Complexity** - Shows real dependencies (JSS, LDAP) that need consideration

### What the PoC References

From existing PKI:
- `org.dogtagpki.est.*` - Backend interfaces and configuration classes
- `com.netscape.certsrv.base.*` - Exception classes
- `org.mozilla.jss.*` - Cryptographic operations (PKCS10, X.509)

These are **intentionally kept** to demonstrate real-world migration challenges.

## What If I Can't Build the Parent PKI?

You can still:

1. **Review the migration patterns** in the source code
2. **Read the comprehensive documentation**:
   - [README.md](README.md) - PoC architecture
   - [MIGRATION-GUIDE.md](MIGRATION-GUIDE.md) - How to migrate other subsystems
   - [TOMCAT-TO-QUARKUS-POC-SUMMARY.md](../../TOMCAT-TO-QUARKUS-POC-SUMMARY.md) - Executive summary

3. **Compare side-by-side**:
   ```bash
   # Tomcat version
   diff -u ../est/src/main/java/org/dogtagpki/est/ESTEngine.java \
           src/main/java/org/dogtagpki/est/quarkus/ESTEngineQuarkus.java
   ```

## Key Takeaways

Even without building, you can see:

### 1. Lifecycle Simplification
**Before (Tomcat):**
```java
@WebListener
public class ESTWebListener implements ServletContextListener {
    public void contextInitialized(ServletContextEvent event) {
        engine = new ESTEngine();
        engine.start(servletContext.getContextPath());
    }
}
```

**After (Quarkus):**
```java
@ApplicationScoped
public class ESTEngineQuarkus {
    void onStart(@Observes StartupEvent event) {
        start();
    }
}
```

### 2. Authentication Modernization
**Before:** Tomcat Valve → ProxyRealm → PKIRealm (100+ lines)
**After:** HttpAuthenticationMechanism + IdentityProvider (50 lines)

### 3. Configuration Type-Safety
**Before:** `props.getProperty("backend.class")` (runtime errors)
**After:** `@ConfigMapping` interfaces (compile-time validation)

### 4. Cloud-Native Features
- Built-in health checks (`/q/health`)
- Metrics endpoints (`/q/metrics`)
- Dev UI (`/q/dev`)
- Native compilation support
- Kubernetes integration

## Next Steps

1. **Read the documentation** to understand patterns
2. **If needed**, build parent PKI following [BUILD.md](BUILD.md)
3. **Experiment** with other subsystems (ACME is next simplest)
4. **Provide feedback** on migration approach

## Troubleshooting

### Q: Why not create a standalone PoC without PKI dependencies?

**A:** That would be a toy example, not a real migration demo. This PoC shows:
- Actual complexity of migration
- Real dependencies to consider (JSS, LDAP)
- How Quarkus frontend can reuse Tomcat backend
- Incremental migration path

### Q: Can I use Docker to avoid installing JSS?

**A:** Yes! Use the Fedora container:
```bash
docker run -it -v $(pwd):/workspace fedora:latest
cd /workspace
dnf install -y maven java-17-openjdk-devel
dnf copr enable @pki/master && dnf install -y jss ldapjdk
```

### Q: What if build.sh fails?

**A:** You can still review the PoC without building. The value is in the architecture, patterns, and documentation.

## Resources

- **PoC Documentation**: [README.md](README.md)
- **Migration Guide**: [MIGRATION-GUIDE.md](MIGRATION-GUIDE.md)
- **Build Guide**: [BUILD.md](BUILD.md)
- **Executive Summary**: [../../TOMCAT-TO-QUARKUS-POC-SUMMARY.md](../../TOMCAT-TO-QUARKUS-POC-SUMMARY.md)
- **Quarkus Guides**: https://quarkus.io/guides/
- **PKI Project**: https://github.com/dogtagpki/pki

---

**Remember:** The main value of this PoC is demonstrating **migration patterns**, not running code. Reading the documentation and source code provides 90% of the value!

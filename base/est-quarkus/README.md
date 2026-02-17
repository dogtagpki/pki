# Dogtag PKI EST Subsystem - Quarkus PoC

This is a **Proof of Concept** migration of the Dogtag PKI EST subsystem from Tomcat to Quarkus.

> **🚀 Try it now with Podman!**
> ```bash
> ./podman-build.sh && ./podman-run.sh
> ```
> See [PODMAN.md](PODMAN.md) for the complete containerized development environment.
>
> **📚 Or just review the architecture:** Read the source code and documentation without building.

## Overview

This PoC demonstrates how the EST subsystem can be migrated from a Tomcat-based architecture to Quarkus, a modern, cloud-native Java framework. The migration addresses key architectural changes:

### What Changed

#### 1. Dependency Migration
- **Tomcat → Quarkus**: Removed all `tomcat-catalina` dependencies
- **javax.servlet → Jakarta EE**: Migrated to Jakarta namespace
- **javax.ws.rs → jakarta.ws.rs**: JAX-RS namespace update
- **RESTEasy 3.x → Quarkus REST**: Modern reactive REST framework

#### 2. Lifecycle Management
- **Before (Tomcat)**:
  ```java
  @WebListener
  public class ESTWebListener implements ServletContextListener {
      public void contextInitialized(ServletContextEvent event) {
          engine.start(servletContext.getContextPath());
      }
  }
  ```

- **After (Quarkus)**:
  ```java
  @ApplicationScoped
  public class ESTEngineQuarkus {
      void onStart(@Observes StartupEvent event) {
          start();
      }
  }
  ```

#### 3. Authentication
- **Before (Tomcat)**: ProxyRealm + SSLAuthenticatorWithFallback + custom Valves
- **After (Quarkus)**: HttpAuthenticationMechanism + IdentityProvider

  ```java
  @ApplicationScoped
  public class ESTCertificateAuthenticationMechanism
          implements HttpAuthenticationMechanism {
      // Certificate-based authentication
  }

  @ApplicationScoped
  public class ESTIdentityProvider
          implements IdentityProvider<CertificateAuthenticationRequest> {
      // Certificate validation and identity creation
  }
  ```

#### 4. Security Constraints
- **Before (Tomcat)**: `web.xml` with `<security-constraint>` elements
- **After (Quarkus)**: `application.yaml` configuration

  ```yaml
  quarkus:
    http:
      auth:
        permission:
          authenticated-post:
            paths: /rest/*
            methods: POST
            policy: authenticated
  ```

#### 5. Request Context
- **Before (Tomcat)**:
  ```java
  @Context
  protected HttpServletRequest servletRequest;

  // Get client certs
  X509Certificate[] certs = (X509Certificate[])
      servletRequest.getAttribute(Globals.CERTIFICATES_ATTR);
  ```

- **After (Quarkus)**:
  ```java
  @Context
  HttpServerRequest httpRequest;

  @Inject
  SecurityIdentity securityIdentity;

  // Get client certs
  javax.net.ssl.SSLSession sslSession = httpRequest.sslSession();
  X509Certificate[] certs = sslSession.getPeerCertificates();
  ```

#### 6. Configuration
- **Before (Tomcat)**: Properties files loaded manually
- **After (Quarkus)**: MicroProfile Config with type-safe interfaces

  ```java
  @ConfigMapping(prefix = "est")
  public interface ESTConfig {
      String instanceId();
      BackendConfig backend();
  }
  ```

## Architecture Comparison

### Tomcat Architecture
```
┌──────────────────────────────────────────┐
│ Tomcat Container                         │
├──────────────────────────────────────────┤
│ ESTWebListener (ServletContextListener)  │
│   └─> Creates ESTEngine singleton        │
│                                          │
│ ExternalAuthenticationValve              │
│   └─> SSLAuthenticatorWithFallback      │
│       └─> ProxyRealm                     │
│           └─> PKIRealm (LDAP/DB)         │
│                                          │
│ ESTApplication (JAX-RS)                  │
│   └─> ESTFrontend (@Context HttpServlet)│
└──────────────────────────────────────────┘
```

### Quarkus Architecture
```
┌──────────────────────────────────────────┐
│ Quarkus Runtime                          │
├──────────────────────────────────────────┤
│ ESTEngineQuarkus (@ApplicationScoped)    │
│   └─> @Observes StartupEvent            │
│                                          │
│ ESTCertificateAuthenticationMechanism    │
│   └─> ESTIdentityProvider               │
│       └─> SecurityIdentity creation      │
│                                          │
│ ESTApplicationQuarkus (JAX-RS)           │
│   └─> ESTFrontendQuarkus                 │
│       └─> @Inject SecurityIdentity       │
│       └─> @Context HttpServerRequest     │
└──────────────────────────────────────────┘
```

## Building the PoC

### Prerequisites
- Java 17 or later
- Maven 3.8+
- Quarkus CLI (optional)

### Build Commands

```bash
# Navigate to PoC directory
cd base/est-quarkus

# Compile and package
mvn clean package

# Run in dev mode (with hot reload)
mvn quarkus:dev

# Build native image (requires GraalVM)
mvn package -Pnative

# Run tests
mvn test
```

## Running the PoC

### Development Mode

```bash
mvn quarkus:dev
```

Access the application at:
- HTTP: http://localhost:8080/rest
- HTTPS: https://localhost:8443/rest

### Production Mode

```bash
# JVM mode
java -jar target/quarkus-app/quarkus-run.jar

# Native mode (if built with -Pnative)
./target/pki-est-quarkus-11.6.0-SNAPSHOT-runner
```

## Configuration

The PoC uses `application.yaml` for configuration. Key settings:

```yaml
est:
  instance-id: ${EST_INSTANCE_ID:ROOT}
  config-dir: ${EST_CONFIG_DIR:/etc/pki/pki-tomcat/est}
  backend:
    config-file: ${est.config-dir}/backend.conf
  authorizer:
    config-file: ${est.config-dir}/authorizer.conf
  realm:
    config-file: ${est.config-dir}/realm.conf
```

Override via environment variables:
```bash
export EST_INSTANCE_ID=my-est
export EST_CONFIG_DIR=/custom/path
mvn quarkus:dev
```

## Testing EST Endpoints

### Get CA Certificates
```bash
curl -k https://localhost:8443/rest/cacerts
```

### Enroll Certificate (requires client cert)
```bash
curl -k \
  --cert client.pem \
  --key client-key.pem \
  -H "Content-Type: application/pkcs10" \
  --data-binary @csr.p10 \
  https://localhost:8443/rest/simpleenroll
```

## What's Not Included in PoC

This PoC focuses on core migration patterns. The following are simplified or stubbed:

1. **Realm Integration**: ESTRealmQuarkus is a stub. Production would integrate with LDAP/database.
2. **JSS/NSS Integration**: Dependencies included but not fully tested with native crypto operations.
3. **Backend Implementation**: Assumes existing `ESTBackend` implementations work unchanged.
4. **Comprehensive Testing**: Basic structure only; full integration tests needed.
5. **Native Compilation**: May require additional GraalVM configuration for JSS.

## Performance Characteristics

### Startup Time
- **Tomcat (original)**: ~5-8 seconds
- **Quarkus JVM**: ~1-2 seconds
- **Quarkus Native**: ~0.05 seconds

### Memory Usage
- **Tomcat (original)**: ~200-300 MB
- **Quarkus JVM**: ~100-150 MB
- **Quarkus Native**: ~30-50 MB

### Request Throughput
- **Tomcat**: Baseline
- **Quarkus JVM**: ~10-15% improvement
- **Quarkus Native**: ~15-20% improvement

*(Performance numbers are estimates for illustration purposes)*

## Next Steps for Full Migration

1. **Complete Realm Integration**
   - Implement full LDAP/database authentication
   - Port PKIRealm functionality
   - Add role-based access control

2. **JSS/NSS Testing**
   - Validate cryptographic operations with JSS
   - Test certificate verification
   - Ensure NSS database access works

3. **Configuration Migration**
   - Create migration scripts from Tomcat config to Quarkus config
   - Support backward compatibility with existing config files

4. **Testing**
   - Port existing EST integration tests
   - Add Quarkus-specific tests
   - Performance benchmarking

5. **Native Compilation**
   - Configure GraalVM reflection for JSS classes
   - Add native-image configuration
   - Test native binary with full functionality

6. **Docker/Kubernetes**
   - Create Quarkus-optimized container images
   - Add Kubernetes health checks and metrics
   - Create deployment manifests

## Benefits of Quarkus Migration

1. **Faster Startup**: Critical for containerized deployments and autoscaling
2. **Lower Memory Footprint**: Better resource utilization in cloud environments
3. **Native Compilation**: Option for ultra-fast startup and minimal memory usage
4. **Developer Experience**: Live reload, better dev mode, modern tooling
5. **Cloud Native**: Built-in Kubernetes integration, health checks, metrics
6. **Future Proof**: Active development, modern Java features, reactive programming

## Limitations and Risks

1. **JSS/NSS Compatibility**: Deep integration with Mozilla NSS may have issues
2. **Breaking Changes**: API changes may impact other subsystems
3. **Community Support**: Tomcat is well-established; Quarkus migration is uncharted
4. **Learning Curve**: Team needs to learn Quarkus patterns and best practices
5. **Native Compilation Challenges**: Not all Java libraries work in native mode

## Files Created

```
base/est-quarkus/
├── pom.xml                                    # Maven build configuration
├── README.md                                  # This file
└── src/
    └── main/
        ├── java/org/dogtagpki/est/quarkus/
        │   ├── ESTConfig.java                 # Configuration mapping
        │   ├── ESTEngineQuarkus.java          # Core engine (CDI)
        │   ├── ESTRealmQuarkus.java           # Realm stub
        │   ├── ESTApplicationQuarkus.java     # JAX-RS application
        │   ├── ESTFrontendQuarkus.java        # REST endpoints
        │   ├── ESTCertificateAuthenticationMechanism.java  # Authentication
        │   ├── ESTIdentityProvider.java       # Identity provider
        │   ├── HandleBadAcceptHeaderRequestFilterQuarkus.java  # Request filter
        │   ├── ReformatContentTypeResponseFilterQuarkus.java   # Response filter
        │   └── PKIExceptionMapperQuarkus.java # Exception mapping
        └── resources/
            └── application.yaml               # Quarkus configuration
```

## Conclusion

This PoC demonstrates that migrating the EST subsystem from Tomcat to Quarkus is feasible. The core patterns translate well, and the resulting application benefits from Quarkus's modern architecture. However, full migration requires careful attention to:

- JSS/NSS cryptographic integration
- Authentication and authorization completeness
- Thorough testing and validation
- Performance benchmarking
- Production deployment considerations

The PoC serves as a foundation for evaluating whether a full Tomcat-to-Quarkus migration makes sense for Dogtag PKI.

## License

Copyright Red Hat, Inc.

SPDX-License-Identifier: GPL-2.0-or-later

# Tomcat to Quarkus Migration Guide

This guide provides step-by-step instructions for migrating PKI subsystems from Tomcat to Quarkus, based on the EST subsystem PoC.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Migration Steps](#migration-steps)
3. [Common Patterns](#common-patterns)
4. [Troubleshooting](#troubleshooting)
5. [Checklist](#checklist)

## Prerequisites

### Required Knowledge
- Java 17 features and syntax
- JAX-RS (RESTful web services)
- CDI (Contexts and Dependency Injection)
- Maven build system
- Basic Quarkus concepts

### Tools
- Java Development Kit (JDK) 17+
- Apache Maven 3.8+
- Quarkus CLI (recommended): `curl -Ls https://sh.jbang.dev | bash -s - app install --fresh --force quarkus@quarkusio`
- IDE with Quarkus support (IntelliJ IDEA, VS Code with Quarkus extension, Eclipse)

## Migration Steps

### Step 1: Create Quarkus Project Structure

```bash
# Option 1: Using Quarkus CLI
quarkus create app org.dogtagpki.pki:pki-<subsystem>-quarkus:11.6.0-SNAPSHOT \
    --extension=rest,rest-jackson,security,config-yaml,logging-json

# Option 2: Manual directory creation
mkdir -p base/<subsystem>-quarkus/src/main/{java,resources}
mkdir -p base/<subsystem>-quarkus/src/test/java
```

### Step 2: Update pom.xml

Key dependencies to include:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.quarkus.platform</groupId>
            <artifactId>quarkus-bom</artifactId>
            <version>3.17.4</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <!-- Core Quarkus -->
    <dependency>
        <groupId>io.quarkus</groupId>
        <artifactId>quarkus-arc</artifactId>
    </dependency>
    <dependency>
        <groupId>io.quarkus</groupId>
        <artifactId>quarkus-rest</artifactId>
    </dependency>
    <dependency>
        <groupId>io.quarkus</groupId>
        <artifactId>quarkus-rest-jackson</artifactId>
    </dependency>

    <!-- Security -->
    <dependency>
        <groupId>io.quarkus</groupId>
        <artifactId>quarkus-security</artifactId>
    </dependency>

    <!-- Keep existing PKI dependencies -->
    <!-- Exclude tomcat-catalina from jss-tomcat -->
</dependencies>
```

### Step 3: Migrate ServletContextListener to CDI Lifecycle

**Before (Tomcat):**
```java
@WebListener
public class CAWebListener implements ServletContextListener {
    public void contextInitialized(ServletContextEvent event) {
        engine = new CAEngine();
        event.getServletContext().setAttribute("engine", engine);
        engine.start();
    }

    public void contextDestroyed(ServletContextEvent event) {
        engine.shutdown();
    }
}
```

**After (Quarkus):**
```java
@ApplicationScoped
public class CAEngineQuarkus {

    void onStart(@Observes StartupEvent event) {
        // Initialization logic
        start();
    }

    void onStop(@Observes ShutdownEvent event) {
        // Cleanup logic
        shutdown();
    }

    private void start() {
        logger.info("Starting CA engine");
        // Engine initialization
    }

    private void shutdown() {
        logger.info("Stopping CA engine");
        // Engine cleanup
    }
}
```

### Step 4: Migrate JAX-RS Resources

**Before (Tomcat):**
```java
@Path("/certs")
public class CertResource extends PKIService {

    @Context
    protected HttpServletRequest servletRequest;

    @GET
    @Path("{id}")
    public Response getCert(@PathParam("id") String id) {
        // Get cert from servlet context
        CMSEngine engine = (CMSEngine)
            servletRequest.getServletContext().getAttribute("engine");

        // Business logic
    }
}
```

**After (Quarkus):**
```java
@Path("/certs")
public class CertResourceQuarkus {

    @Inject
    CAEngineQuarkus engine;  // CDI injection instead of servlet context

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    HttpServerRequest httpRequest;  // Vert.x HTTP request

    @GET
    @Path("{id}")
    public Response getCert(@PathParam("id") String id) {
        // Use injected engine
        // Business logic
    }
}
```

### Step 5: Migrate Authentication

#### 5.1 Create HttpAuthenticationMechanism

```java
@ApplicationScoped
public class PKICertificateAuthenticationMechanism
        implements HttpAuthenticationMechanism {

    @Override
    public Uni<SecurityIdentity> authenticate(
            RoutingContext context,
            IdentityProviderManager identityProviderManager) {

        // Extract client certificate
        SSLSession sslSession = context.request().sslSession();
        X509Certificate cert = (X509Certificate)
            sslSession.getPeerCertificates()[0];

        // Create authentication request
        CertificateAuthenticationRequest authRequest =
            new CertificateAuthenticationRequest(cert);

        // Delegate to identity provider
        return identityProviderManager.authenticate(authRequest);
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        return Uni.createFrom().item(
            new ChallengeData(401, "WWW-Authenticate", "Certificate")
        );
    }
}
```

#### 5.2 Create IdentityProvider

```java
@ApplicationScoped
public class PKIIdentityProvider
        implements IdentityProvider<CertificateAuthenticationRequest> {

    @Inject
    PKIEngineQuarkus engine;

    @Override
    public Class<CertificateAuthenticationRequest> getRequestType() {
        return CertificateAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(
            CertificateAuthenticationRequest request,
            AuthenticationRequestContext context) {

        X509Certificate cert = request.getCertificate().getCertificate();

        // Validate certificate (integrate with PKIRealm logic)
        cert.checkValidity();

        // Build security identity
        QuarkusSecurityIdentity.Builder builder =
            QuarkusSecurityIdentity.builder();
        builder.setPrincipal(new QuarkusPrincipal(extractCN(cert)));
        builder.addRole("pki-user");
        builder.addCredential(request.getCertificate());

        return Uni.createFrom().item(builder.build());
    }
}
```

### Step 6: Migrate Configuration

#### 6.1 Create Config Interface

```java
@ConfigMapping(prefix = "pki.ca")
public interface CAConfig {
    String instanceId();
    String configDir();

    BackendConfig backend();

    interface BackendConfig {
        String className();
        Map<String, String> parameters();
    }
}
```

#### 6.2 Create application.yaml

```yaml
pki:
  ca:
    instance-id: ${CA_INSTANCE_ID:pki-ca}
    config-dir: ${CA_CONFIG_DIR:/etc/pki/pki-tomcat/ca}
    backend:
      class-name: com.netscape.cmscore.apps.CABackend
      parameters:
        # Backend parameters
```

#### 6.3 Inject Configuration

```java
@ApplicationScoped
public class CAEngineQuarkus {

    @Inject
    CAConfig config;

    void onStart(@Observes StartupEvent event) {
        logger.info("CA instance: {}", config.instanceId());
        logger.info("CA config dir: {}", config.configDir());
    }
}
```

### Step 7: Migrate Security Constraints

**Before (web.xml):**
```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/rest/admin/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
    <user-data-constraint>
        <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
</security-constraint>
```

**After (application.yaml):**
```yaml
quarkus:
  http:
    auth:
      permission:
        admin-api:
          paths: /rest/admin/*
          policy: authenticated
          roles: admin

    ssl-port: 8443
    insecure-requests: REDIRECT  # Force HTTPS
```

### Step 8: Update Namespace Imports

Replace all imports:
```java
// Before
import javax.ws.rs.*;
import javax.servlet.http.*;
import javax.enterprise.context.*;

// After
import jakarta.ws.rs.*;
import jakarta.servlet.http.*;  // Only if needed
import jakarta.enterprise.context.*;
```

### Step 9: Handle RESTEasy-Specific Code

**Remove RESTEasy Internals:**
```java
// Before (Tomcat with RESTEasy 3.x)
@Context
private ResourceMethodInvoker methodInvoker;

Method method = (Method) requestContext.getProperty(
    "org.jboss.resteasy.core.ResourceMethodInvoker"
);

// After (Quarkus)
@Context
private ResourceInfo resourceInfo;

Method method = resourceInfo.getResourceMethod();
```

### Step 10: Testing

#### 10.1 Create Quarkus Test

```java
@QuarkusTest
public class CertResourceTest {

    @Test
    public void testGetCert() {
        given()
            .when()
            .get("/rest/certs/1")
            .then()
            .statusCode(200)
            .body("id", equalTo("1"));
    }
}
```

#### 10.2 Test with TestContainers

```java
@QuarkusTest
@QuarkusTestResource(LdapTestResource.class)
public class AuthenticationTest {

    @Test
    public void testCertAuth() {
        // Test with client certificate
    }
}
```

## Common Patterns

### Pattern 1: Singleton → CDI Bean

```java
// Before
public class MyService {
    private static MyService instance;
    public static MyService getInstance() {
        return instance;
    }
}

// After
@ApplicationScoped
public class MyServiceQuarkus {
    // CDI manages lifecycle
}
```

### Pattern 2: ServletContext Attributes → CDI Injection

```java
// Before
Object obj = servletContext.getAttribute("myObject");

// After
@Inject
MyObject myObject;
```

### Pattern 3: Properties Files → MicroProfile Config

```java
// Before
Properties props = new Properties();
try (FileReader reader = new FileReader(file)) {
    props.load(reader);
}
String value = props.getProperty("key");

// After
@ConfigProperty(name = "my.key")
String value;
```

### Pattern 4: Servlet Filters → JAX-RS Filters

```java
// Before
public class MyFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res,
                        FilterChain chain) {
        // Filter logic
        chain.doFilter(req, res);
    }
}

// After
@Provider
public class MyFilterQuarkus implements ContainerRequestFilter {
    public void filter(ContainerRequestContext requestContext) {
        // Filter logic
    }
}
```

## Troubleshooting

### Issue: Native Compilation Fails

**Symptom:** GraalVM native-image fails with reflection errors

**Solution:** Add reflection configuration
```json
// src/main/resources/META-INF/native-image/reflect-config.json
[
  {
    "name": "com.netscape.cmscore.apps.CAEngine",
    "allDeclaredConstructors": true,
    "allPublicMethods": true
  }
]
```

### Issue: JSS/NSS Integration Problems

**Symptom:** JNI errors when accessing native crypto

**Solution:** Ensure JSS native libraries are available
```yaml
quarkus:
  native:
    additional-build-args:
      - -H:+JNI
      - -H:IncludeResourceBundles=jss.properties
```

### Issue: Security Constraints Not Applied

**Symptom:** Endpoints accessible without authentication

**Solution:** Verify configuration and add @Authenticated
```java
@GET
@Path("/admin")
@Authenticated  // Explicit annotation
public Response adminEndpoint() {
    // ...
}
```

### Issue: CDI Injection Fails

**Symptom:** NullPointerException on @Inject fields

**Solution:** Ensure beans are @ApplicationScoped and package is scanned
```yaml
quarkus:
  arc:
    exclude-types:
      - com.example.NotABean
```

## Checklist

Use this checklist for each subsystem migration:

- [ ] Project structure created
- [ ] pom.xml updated with Quarkus dependencies
- [ ] ServletContextListener → CDI lifecycle events
- [ ] JAX-RS resources updated (jakarta namespace)
- [ ] HttpServletRequest → HttpServerRequest/SecurityIdentity
- [ ] Authentication mechanism implemented
- [ ] Identity provider implemented
- [ ] Security constraints migrated
- [ ] Configuration migrated to MicroProfile Config
- [ ] Servlet filters → JAX-RS filters
- [ ] Exception mappers updated
- [ ] RESTEasy-specific code removed
- [ ] Unit tests created
- [ ] Integration tests created
- [ ] Documentation updated
- [ ] Performance benchmarking done
- [ ] Native compilation tested (if required)

## Next Steps

1. **Review the EST PoC** in `base/est-quarkus/` for reference implementation
2. **Start with simpler subsystems** (ACME, OCSP) before tackling CA/KRA
3. **Test incrementally** - don't migrate everything at once
4. **Maintain parallel codebases** during transition
5. **Document subsystem-specific challenges** and solutions

## Additional Resources

- [Quarkus Documentation](https://quarkus.io/guides/)
- [Quarkus Security Guide](https://quarkus.io/guides/security)
- [MicroProfile Config Specification](https://github.com/eclipse/microprofile-config)
- [CDI Reference](https://jakarta.ee/specifications/cdi/)
- [Jakarta RESTful Web Services](https://jakarta.ee/specifications/restful-ws/)

## Support

For questions or issues with migration:

1. Review this guide and EST PoC implementation
2. Check Quarkus documentation and guides
3. Search Quarkus GitHub issues
4. Ask on Dogtag PKI development mailing list

---

**Note:** This is a living document. Please update with lessons learned during migration of other subsystems.

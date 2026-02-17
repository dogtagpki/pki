# Tomcat to Quarkus Migration

## Executive Summary

This migration adds parallel Quarkus deployment modules for all seven Dogtag PKI subsystems (CA, KRA, OCSP, TKS, TPS, ACME, EST), enabling each subsystem to run as an independent Quarkus process instead of sharing a single Tomcat JVM. The existing Tomcat deployment remains fully functional and buildable. The Quarkus modules are activated via the `-Pquarkus` Maven profile.

The migration was implemented in 9 phases, progressing from foundational abstractions through each subsystem in order of complexity, and finishing with infrastructure (Python tooling, systemd, containers).

**Branch**: `tomcat-to-quarkus-migration`
**PR**: https://github.com/czinda/pki/pull/1
**Files changed**: 185 (21,072 insertions, 564 deletions)

---

## Motivation

The current Tomcat-based architecture runs all subsystems inside a single JVM. This creates several limitations:

- **Tight coupling**: Core classes reference Tomcat APIs directly (`GenericPrincipal`, `RealmBase`, `catalina.base`, `TomcatJSS`)
- **Shared failure domain**: A crash in one subsystem brings down all subsystems
- **Heavyweight deployment**: Every instance requires a full Tomcat installation even for a single subsystem
- **Scaling constraints**: Cannot scale individual subsystems independently
- **Container-unfriendly**: The multi-subsystem-per-process model conflicts with container best practices (one process per container)

Quarkus provides faster startup, lower memory footprint, CDI-based dependency injection, and a container-native design that aligns with modern deployment patterns.

---

## Architecture

### Dependency Graph

```
pki-common (unchanged)
    |
pki-server-core (NEW - business logic, no Tomcat/Servlet deps)
    |
    +-- pki-server (MODIFIED - thin Tomcat adapter, depends on server-core)
    |       +-- pki-tomcat-9.0 / pki-tomcat-10.1
    |       +-- pki-server-webapp
    |       +-- pki-ca, pki-kra, pki-ocsp, etc. (existing Tomcat deployments)
    |
    +-- pki-quarkus-common (NEW - shared Quarkus adapters)
            +-- pki-est-quarkus
            +-- pki-acme-quarkus
            +-- pki-ocsp-quarkus
            +-- pki-kra-quarkus
            +-- pki-tks-quarkus
            +-- pki-tps-quarkus
            +-- pki-ca-quarkus
```

### Key Design Decisions

1. **Parallel modules, not replacement**: Quarkus modules exist alongside Tomcat modules. Both are buildable from the same source tree.
2. **Shared core library**: Business logic extracted into `pki-server-core` with no container dependencies, reused by both Tomcat and Quarkus adapters.
3. **CDI engine wrappers**: Each subsystem engine (e.g., `CAEngine`) is wrapped in an `@ApplicationScoped` CDI bean that manages lifecycle via `@Observes StartupEvent/ShutdownEvent`.
4. **JAX-RS resources**: Tomcat V2 servlets are converted to standard JAX-RS `@Path` resources with `@Inject` for dependency injection.
5. **Quarkus Security**: Tomcat's `PKIRealm`/`GenericPrincipal` replaced with Quarkus `HttpAuthenticationMechanism`/`IdentityProvider`/`SecurityIdentity`.

---

## Phase-by-Phase Summary

### Phase 0: Foundation

Created the container-agnostic core library and shared Quarkus adapter library that all subsequent phases depend on.

#### `base/server-core/` -- Container-Agnostic Core

| File | Purpose |
|------|---------|
| `InstanceConfig.java` | Interface replacing `CMS.getInstanceDir()` which reads `catalina.base` |
| `TomcatInstanceConfig.java` | Implementation reading `catalina.base` system property |
| `QuarkusInstanceConfig.java` | Implementation reading `pki.instance.dir` system property |
| `PKIPrincipalCore.java` | Container-agnostic principal carrying `User`, `AuthToken`, and roles (replaces dependency on Tomcat's `GenericPrincipal`) |
| `SocketListenerRegistry.java` | Interface abstracting `TomcatJSS.getInstance()` for crypto/SSL initialization |

#### `base/quarkus-common/` -- Shared Quarkus Adapters

| File | Purpose |
|------|---------|
| `PKICertificateAuthenticationMechanism.java` | Extracts client certificate from TLS and creates `CertificateAuthenticationRequest` |
| `PKIIdentityProvider.java` | Authenticates certificates via `PKIAuthenticator`, produces `SecurityIdentity` with `PKIPrincipalCore` |
| `PKIPasswordIdentityProvider.java` | Authenticates username/password via `PKIAuthenticator` |
| `QuarkusACLFilter.java` | `ContainerRequestFilter` delegating to `ACLChecker` |
| `QuarkusAuthMethodFilter.java` | `ContainerRequestFilter` delegating to `AuthMethodChecker` |
| `QuarkusSocketListenerRegistry.java` | Direct JSS initialization without Tomcat |

#### Modifications to Existing Code

| File | Change |
|------|--------|
| `CMS.java` | Delegate instance directory resolution to `InstanceConfig` |
| `CMSEngine.java` | Accept `SocketListenerRegistry` instead of calling `TomcatJSS` directly |
| `PKIPrincipal.java` | Wrap/delegate to `PKIPrincipalCore` |
| `PKIRealm.java` | Delegate authentication logic to new `PKIAuthenticator` class |
| `ACLFilter.java` | Delegate business logic to new `ACLChecker` class |
| `AuthMethodFilter.java` | Delegate business logic to new `AuthMethodChecker` class |

New classes added to `pki-server`:

| File | Purpose |
|------|---------|
| `PKIAuthenticator.java` | Pure Java authentication logic extracted from `PKIRealm` (password auth, cert auth, role lookup) |
| `ACLChecker.java` | ACL enforcement logic extracted from `ACLFilter` |
| `AuthMethodChecker.java` | Auth method validation logic extracted from `AuthMethodFilter` |
| `TomcatSocketListenerRegistry.java` | `SocketListenerRegistry` implementation calling `TomcatJSS` |

---

### Phase 1: EST Quarkus

**Module**: `base/est-quarkus/` (10 Java files)

Integrated the existing EST PoC with the shared libraries. The EST subsystem is the simplest, making it ideal for validating the migration pattern.

| Resource | Path | Operations |
|----------|------|------------|
| `ESTFrontendQuarkus` | `/rest/*` | `cacerts`, `simpleenroll`, `simplereenroll`, `csrattrs`, `serverkeygen` |

Key files: `ESTEngineQuarkus.java` (CDI wrapper), `ESTIdentityProvider.java`, `ESTCertificateAuthenticationMechanism.java`

---

### Phase 2: ACME Quarkus

**Module**: `base/acme-quarkus/` (21 Java files)

The ACME protocol requires 14 distinct endpoints plus an engine managing account, order, authorization, and challenge lifecycle.

| Resource | Path | Operations |
|----------|------|------------|
| `ACMEDirectoryResource` | `/acme/directory` | Directory metadata |
| `ACMENonceResource` | `/acme/new-nonce` | Replay nonce management |
| `ACMENewAccountResource` | `/acme/new-account` | Account creation |
| `ACMENewOrderResource` | `/acme/new-order` | Order creation |
| `ACMEOrderResource` | `/acme/order/{id}` | Order retrieval, finalization |
| `ACMEAuthorizationResource` | `/acme/authz/{id}` | Authorization retrieval |
| `ACMEChallengeResource` | `/acme/challenge/{id}/{type}` | Challenge validation |
| `ACMECertificateResource` | `/acme/cert/{id}` | Certificate download |
| `ACMEAccountResource` | `/acme/acct/{id}` | Account management |
| `ACMERevocationResource` | `/acme/revoke-cert` | Certificate revocation |
| `ACMELoginResource` | `/acme/login` | Login |
| `ACMELogoutResource` | `/acme/logout` | Logout |
| `ACMEAdminResource` | `/acme/admin/*` | Enable/disable ACME |

Key files: `ACMEEngineQuarkus.java` (959 lines, wrapping the 1123-line `ACMEEngine`), `ACMEChallengeProcessorQuarkus.java`, `ACMEEnableFilterQuarkus.java`

---

### Phase 3: OCSP Quarkus

**Module**: `base/ocsp-quarkus/` (13 Java files)

| Resource | Path | Operations |
|----------|------|------------|
| `OCSPResponderResource` | `/v2/ocsp/*` | OCSP request processing (GET/POST) |
| `OCSPAccountResource` | `/v2/account` | Account login/logout |
| `OCSPAuditResource` | `/v2/audit` | Audit log access |
| `OCSPGroupResource` | `/v2/admin/groups` | Group CRUD |
| `OCSPUserResource` | `/v2/admin/users` | User CRUD + cert management |
| `OCSPJobResource` | `/v2/jobs` | Job management |
| `OCSPSecurityDomainResource` | `/v2/securityDomain` | Domain info and install token |
| `OCSPSelfTestResource` | `/v2/selftests` | Self-test execution |

---

### Phase 4: KRA Quarkus

**Module**: `base/kra-quarkus/` (16 Java files)

| Resource | Path | Operations |
|----------|------|------------|
| `KRAKeyResource` | `/v2/agent/keys` | Key listing, retrieval, recovery |
| `KRAKeyRequestResource` | `/v2/agent/keyrequests` | Key request management |
| `KRAInfoResource` | `/v2/info` | KRA info + archival mechanisms |
| `KRASystemCertResource` | `/v2/config/cert` | Transport/storage certs |
| Standard admin resources | Various | Account, audit, groups, users, jobs, security domain, self-tests |

---

### Phase 5: TKS Quarkus

**Module**: `base/tks-quarkus/` (13 Java files)

| Resource | Path | Operations |
|----------|------|------------|
| `TKSTPSConnectorResource` | `/v2/admin/tpsconnectors` | TPS connector CRUD |
| Standard admin resources | Various | Account, audit, groups, users, jobs, security domain, self-tests |

---

### Phase 6: TPS Quarkus

**Module**: `base/tps-quarkus/` (20 Java files)

The TPS is a complex subsystem with token lifecycle management, profile mappings, connectors, and activity tracking.

| Resource | Path | Operations |
|----------|------|------------|
| `TPSTokenResource` | `/v2/tokens` | Token CRUD, status changes (683 lines) |
| `TPSProfileResource` | `/v2/profiles` | TPS profile CRUD + state management |
| `TPSProfileMappingResource` | `/v2/profile-mappings` | Profile mapping CRUD + state |
| `TPSAuthenticatorResource` | `/v2/authenticators` | Authenticator CRUD + state |
| `TPSConnectorResource` | `/v2/connectors` | Connector CRUD + state |
| `TPSActivityResource` | `/v2/activities` | Activity log listing |
| `TPSCertResource` | `/v2/tokens/{id}/certs` | Token certificate listing |
| `TPSConfigResource` | `/v2/config` | TPS configuration management |
| Standard admin resources | Various | Account, audit, groups, users, jobs, security domain, self-tests |

---

### Phase 7: CA Quarkus

**Module**: `base/ca-quarkus/` (22 Java files)

The CA is the most complex subsystem (528 Java files, 2523-line `CAEngine`, 20 V2 servlets, 26 V2 filters in the original Tomcat module).

| Resource | Path | Operations |
|----------|------|------------|
| `CACertResource` | `/v2/certs` | Certificate listing, retrieval, search |
| `CACertRequestResource` | `/v2/certrequests` | Enrollment templates, request info |
| `CAAgentCertResource` | `/v2/agent/certs` | Agent cert review, revocation, unrevocation |
| `CAAgentCertRequestResource` | `/v2/agent/certrequests` | Request listing, review, approve/reject/cancel |
| `CAProfileResource` | `/v2/profiles` | Profile CRUD + raw profile + state management |
| `CAAuthorityResource` | `/v2/authorities` | Sub-CA CRUD, cert/chain retrieval, enable/disable/renew |
| `CASystemCertResource` | `/v2/config/cert` | Signing and transport certificate retrieval |
| `CAKRAConnectorResource` | `/v2/admin/kraconnector` | KRA connector management |
| `CAInfoResource` | `/v2/info` | CA information |
| `CAFeatureResource` | `/v2/config/features` | Feature listing |
| Standard admin resources | Various | Account, audit, groups, users, jobs, security domain, self-tests |

#### Key Tomcat Coupling Points Resolved

| Tomcat Coupling | Solution |
|-----------------|----------|
| `GenericPrincipal` in `AgentCertServlet` for role checks | `CAEngineQuarkus.toPKIPrincipal(SecurityIdentity)` bridge method |
| `PKIPrincipal.getAuthToken()` in `AgentCertRequestServlet` | Extract `PKIPrincipalCore` from `SecurityIdentity` attribute |
| `EnrollmentProcessor`/`RenewalProcessor` requiring `HttpServletRequest` | Documented limitation; throws `PKIException` noting servlet bridge needed |
| Session-based nonce management | Omitted; noted for future alternative mechanism |
| 26 ACL/AuthMethod filter pairs | Replaced by `application.yaml` security constraints |

#### Not Migrated

- `CAInstallerServlet` -- pre-operation only, runs during `pkispawn` setup
- `DashboardServlet` -- new feature, not part of core CA functionality

---

### Phase 8: Python Tooling

| File | Purpose |
|------|---------|
| `base/server/python/pki/server/quarkus.py` | `QuarkusPKIInstance` class for managing Quarkus-based PKI instances |
| `base/server/share/lib/systemd/system/pki-quarkusd@.service` | systemd service template for individual Quarkus subsystem processes |
| `base/server/share/lib/systemd/system/pki-quarkusd.target` | systemd target grouping all Quarkus PKI services |

#### QuarkusPKIInstance Class

Provides full lifecycle management for Quarkus-based subsystems:

- **Properties**: `base_dir`, `conf_dir`, `logs_dir`, `alias_dir`, `cs_cfg`, `application_yaml`, `runner_jar`, `service_name`
- **Lifecycle**: `create()`, `remove()`, `start()`, `stop()`, `restart()`, `is_running()`, `status()`
- **Utilities**: `get_java_command()`, `generate_application_yaml()`, `find_instances()`

#### systemd Service Template

```
pki-quarkusd@<instance>-<subsystem>.service
```

- Runs as `pkiuser` with `Type=simple`
- Security hardening: `ProtectSystem=full`, `ProtectHome=true`, `NoNewPrivileges=true`, `PrivateTmp=true`
- Automatic restart on failure with 10-second delay

---

### Phase 9: Packaging and Containers

| File | Purpose |
|------|---------|
| `Containerfile.quarkus` | Multi-stage container build for per-subsystem images |
| `build.sh` (modified) | Added `--with-quarkus` / `--without-quarkus` flags |
| `pki.spec` (modified) | Added Quarkus subpackage references |
| `pom.xml` (modified) | Added `quarkus.platform.version` property |

#### Container Usage

```bash
# Build a CA Quarkus container
podman build -f Containerfile.quarkus \
  --build-arg SUBSYSTEM=ca \
  -t pki-ca-quarkus .

# Run it
podman run -d \
  -p 8443:8443 \
  -v /etc/pki/pki-tomcat:/etc/pki/pki-tomcat:Z \
  -v /var/lib/pki/pki-tomcat:/var/lib/pki/pki-tomcat:Z \
  pki-ca-quarkus
```

---

## Module Inventory

| Module | Java Files | Description |
|--------|-----------|-------------|
| `base/server-core` | 5 | Container-agnostic core library |
| `base/quarkus-common` | 6 | Shared Quarkus adapters |
| `base/est-quarkus` | 10 | EST protocol |
| `base/acme-quarkus` | 21 | ACME protocol |
| `base/ocsp-quarkus` | 13 | OCSP responder |
| `base/kra-quarkus` | 16 | Key Recovery Authority |
| `base/tks-quarkus` | 13 | Token Key Service |
| `base/tps-quarkus` | 20 | Token Processing System |
| `base/ca-quarkus` | 22 | Certificate Authority |
| **Total** | **~126** | |

---

## Build Instructions

```bash
# Standard Tomcat-only build (unchanged)
./build.sh dist

# Build with Quarkus modules
./build.sh -Pquarkus dist

# Build with Quarkus using build.sh flags
./build.sh --with-quarkus dist

# Maven directly
cd base && mvn install -Pquarkus
```

---

## Known Limitations

| Limitation | Impact | Future Work |
|------------|--------|-------------|
| `EnrollmentProcessor`/`RenewalProcessor` require `HttpServletRequest` | Direct enrollment via Quarkus CA not fully functional | Add servlet bridge or refactor processors to accept context object |
| Nonce management uses HTTP sessions | CSRF protection not available in Quarkus deployment | Implement token-based nonce mechanism |
| Legacy V1 servlets not migrated | Older clients using V1 API must use Tomcat deployment | Clients should migrate to V2 API |
| `AuthorityRepository.deleteCA()`/`renewCA()` receive null for `HttpServletRequest` | Sub-CA operations may have limited audit context | Refactor to accept audit context object |
| No integration tests yet | Quarkus modules compile but are not tested end-to-end | Add container-based integration tests |

---

## Tomcat vs Quarkus Comparison

| Aspect | Tomcat | Quarkus |
|--------|--------|---------|
| Process model | All subsystems in one JVM | Each subsystem is an independent process |
| Startup | `pki-tomcatd@<instance>.service` | `pki-quarkusd@<instance>-<subsystem>.service` |
| Configuration | `CS.cfg` + `web.xml` + Tomcat context XML | `CS.cfg` + `application.yaml` |
| Authentication | `PKIRealm` extends `RealmBase` | `HttpAuthenticationMechanism` + `IdentityProvider` |
| Authorization | `ACLFilter` extends `HttpFilter` | `QuarkusACLFilter` implements `ContainerRequestFilter` |
| Principal | `PKIPrincipal` extends `GenericPrincipal` | `SecurityIdentity` with `PKIPrincipalCore` attribute |
| REST endpoints | `@WebServlet` + manual dispatch | JAX-RS `@Path` + `@Inject` |
| SSL/TLS | TomcatJSS valve | Direct JSS initialization via `QuarkusSocketListenerRegistry` |
| Container image | Full Tomcat + all subsystems | Minimal JRE + single subsystem |
| Scaling | Scale entire instance | Scale individual subsystems |

---

## Pattern Reference

Each Quarkus subsystem module follows a consistent pattern:

```
base/<subsystem>-quarkus/
  pom.xml                          # Maven module depending on pki-<subsystem>, pki-server-core, pki-quarkus-common
  src/main/java/.../quarkus/
    <Sub>EngineQuarkus.java        # @ApplicationScoped CDI wrapper for <Sub>Engine
    <Sub>ApplicationQuarkus.java   # JAX-RS Application class
    <Sub>IdentityProvider.java     # Quarkus IdentityProvider with subsystem-specific roles
    <Sub>CertificateAuthenticationMechanism.java  # Extends PKICertificateAuthenticationMechanism
    PKIExceptionMapperQuarkus.java # Exception-to-HTTP-response mapper
    <Sub>*Resource.java            # JAX-RS resources (one per V2 servlet)
  src/main/resources/
    application.yaml               # Quarkus config with security constraints
```

### Engine Wrapper Pattern

```java
@ApplicationScoped
public class CAEngineQuarkus {
    private CAEngine engine;

    void onStart(@Observes StartupEvent event) {
        CMS.setInstanceConfig(new QuarkusInstanceConfig());
        engine = new CAEngine();
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());
        engine.start();
    }

    void onStop(@Observes ShutdownEvent event) {
        engine.stop();
    }

    public CAEngine getEngine() { return engine; }
}
```

### Resource Pattern

```java
@Path("v2/certs")
@ApplicationScoped
public class CACertResource {
    @Inject CAEngineQuarkus engineQuarkus;
    @Inject SecurityIdentity identity;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listCerts(@QueryParam("start") Integer start, ...) {
        CAEngine engine = engineQuarkus.getEngine();
        // Business logic using engine
    }
}
```

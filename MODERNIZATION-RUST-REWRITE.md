# Dogtag PKI Modernization: Memory-Safe Rewrite

A comprehensive plan for rewriting Dogtag PKI in a modern, memory-safe language.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Language Selection](#language-selection)
4. [Architecture Vision](#architecture-vision)
5. [Component Mapping](#component-mapping)
6. [Migration Strategy](#migration-strategy)
7. [Risk Assessment](#risk-assessment)
8. [Timeline & Phases](#timeline--phases)
9. [Resource Requirements](#resource-requirements)
10. [Success Criteria](#success-criteria)

---

## Executive Summary

### The Case for Rewriting

Dogtag PKI is a mature, enterprise-grade Certificate Authority system. While the Java components are memory-safe (JVM-managed), the system has:

- **Legacy C/C++ native components** with potential memory safety issues
- **Complex dependency chains** (NSS, JSS, LDAP, Tomcat)
- **Aging architecture** designed for traditional deployments
- **Limited cloud-native capabilities**

### Proposed Approach

**Primary Language: Rust**

Rewrite the PKI system in Rust to achieve:
- Complete memory safety without garbage collection
- High performance for cryptographic operations
- Modern async runtime for scalability
- Cloud-native deployment model
- Reduced attack surface

### Guiding Principles

1. **Incremental migration** - Not a big-bang rewrite
2. **API compatibility** - Existing integrations continue working
3. **Feature parity first** - Match current capabilities before adding new ones
4. **Security audit** - Each component audited before production
5. **Parallel operation** - Run old and new systems side-by-side

---

## Current State Analysis

### Technology Stack

| Layer | Current Technology | Memory Safety |
|-------|-------------------|---------------|
| Application Server | Apache Tomcat 9.0 | ✅ Safe (JVM) |
| Business Logic | Java 11/17 | ✅ Safe (JVM) |
| REST API | RESTEasy/JAX-RS | ✅ Safe (JVM) |
| Cryptography | NSS (C) + JSS (JNI) | ❌ Unsafe (C) |
| Native Tools | C/C++ | ❌ Unsafe |
| CLI Tools | Python 3 | ✅ Safe |
| Database | LDAP (389 DS) | External |
| Web UI | HTML/JS/Backbone | N/A |

### Codebase Size (Approximate)

| Component | Language | Lines of Code | Complexity |
|-----------|----------|---------------|------------|
| CA Subsystem | Java | ~50,000 | High |
| KRA Subsystem | Java | ~25,000 | High |
| OCSP Subsystem | Java | ~10,000 | Medium |
| TKS/TPS Subsystems | Java | ~30,000 | High |
| ACME Responder | Java | ~8,000 | Medium |
| EST Responder | Java | ~5,000 | Low |
| Server Framework | Java | ~80,000 | High |
| Common Libraries | Java | ~40,000 | Medium |
| Python Tools | Python | ~30,000 | Medium |
| Native Tools | C/C++ | ~15,000 | Medium |
| **Total** | | **~300,000** | |

### External Dependencies

| Dependency | Purpose | Replacement Strategy |
|------------|---------|---------------------|
| NSS | Cryptography, PKCS#11 | Rust crypto libraries |
| JSS | Java-NSS bridge | Eliminate (native Rust) |
| LDAP SDK | Directory access | Rust LDAP client |
| Tomcat | HTTP server | Rust async runtime |
| RESTEasy | REST framework | Axum/Actix-web |
| Jackson | JSON processing | Serde |
| 389 DS | Certificate storage | Keep or PostgreSQL |

---

## Language Selection

### Candidates Evaluated

| Language | Memory Safe | GC | Performance | Crypto Ecosystem | Cloud Native |
|----------|-------------|-----|-------------|------------------|--------------|
| **Rust** | ✅ Compile-time | ❌ None | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Go | ✅ Runtime | ✅ Yes | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| C# (.NET) | ✅ Runtime | ✅ Yes | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| Swift | ✅ ARC | ⚡ ARC | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| Zig | ✅ Compile-time | ❌ None | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| Java (current) | ✅ Runtime | ✅ Yes | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |

### Recommendation: Rust

**Why Rust for PKI?**

1. **Memory Safety Without GC**
   - No garbage collection pauses during HSM operations
   - Compile-time guarantees prevent buffer overflows, use-after-free
   - Critical for cryptographic code handling secrets

2. **Performance**
   - Zero-cost abstractions
   - Comparable to C/C++ performance
   - Efficient async I/O for high-throughput certificate operations

3. **Cryptography Ecosystem**
   - `ring` - High-performance crypto primitives
   - `rustls` - Modern TLS implementation
   - `rcgen` - X.509 certificate generation
   - `x509-parser` - Certificate parsing
   - `pkcs11` - PKCS#11/HSM support
   - `openssl` bindings available as fallback

4. **Cloud-Native Ready**
   - Small binary sizes (no runtime)
   - Fast startup times
   - Low memory footprint
   - Excellent container support
   - WebAssembly compilation possible

5. **Security Track Record**
   - Memory safety eliminates entire vulnerability classes
   - Strong type system prevents logic errors
   - Fearless concurrency
   - Used by security-critical projects (Firecracker, curl, Linux kernel)

6. **Industry Momentum**
   - Growing adoption in security-sensitive applications
   - Active maintainers and community
   - Corporate backing (AWS, Google, Microsoft, Meta)

### Potential Concerns & Mitigations

| Concern | Mitigation |
|---------|------------|
| Learning curve | Training program, hire Rust expertise |
| Smaller talent pool | Growing rapidly, Rust consistently top-desired language |
| Library maturity | Key crypto libraries are mature, fallback to C FFI if needed |
| Build times | Incremental compilation, caching, smaller crates |

---

## Architecture Vision

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PKI-RS (Rust PKI Platform)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                          API GATEWAY                                    │ │
│  │                                                                         │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐  │ │
│  │  │  REST API   │  │  ACME API   │  │   EST API   │  │   CMC API     │  │ │
│  │  │  (JSON)     │  │  (RFC 8555) │  │  (RFC 7030) │  │  (RFC 5272)   │  │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────────┘  │ │
│  │                                                                         │ │
│  │  Framework: Axum + Tower (async, middleware-based)                     │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│  ┌───────────────────────────────────┼───────────────────────────────────┐  │
│  │                         CORE SERVICES                                  │  │
│  │                                   │                                    │  │
│  │  ┌─────────────┐  ┌─────────────┐ │ ┌─────────────┐  ┌─────────────┐  │  │
│  │  │     CA      │  │    KRA      │ │ │    OCSP     │  │   CRL       │  │  │
│  │  │  Service    │  │  Service    │ │ │  Responder  │  │  Publisher  │  │  │
│  │  │             │  │             │ │ │             │  │             │  │  │
│  │  │ • Issuance  │  │ • Key Arch  │ │ │ • Status    │  │ • Generate  │  │  │
│  │  │ • Renewal   │  │ • Recovery  │ │ │ • Signing   │  │ • Publish   │  │  │
│  │  │ • Revoke    │  │ • Escrow    │ │ │ • Caching   │  │ • Delta     │  │  │
│  │  └─────────────┘  └─────────────┘ │ └─────────────┘  └─────────────┘  │  │
│  │                                   │                                    │  │
│  │  ┌─────────────┐  ┌─────────────┐ │ ┌─────────────┐  ┌─────────────┐  │  │
│  │  │  Profile    │  │  Workflow   │ │ │   Audit     │  │Notification │  │  │
│  │  │  Engine     │  │   Engine    │ │ │   Logger    │  │   System    │  │  │
│  │  └─────────────┘  └─────────────┘ │ └─────────────┘  └─────────────┘  │  │
│  └───────────────────────────────────┼───────────────────────────────────┘  │
│                                      │                                       │
│  ┌───────────────────────────────────┼───────────────────────────────────┐  │
│  │                      CRYPTOGRAPHY LAYER                                │  │
│  │                                   │                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                    Crypto Provider Abstraction                   │  │  │
│  │  │                                                                  │  │  │
│  │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐ │  │  │
│  │  │  │   Ring    │  │  AWS LC   │  │  RustCrypto│  │  PKCS#11/HSM │ │  │  │
│  │  │  │ (default) │  │  (FIPS)   │  │            │  │              │ │  │  │
│  │  │  └───────────┘  └───────────┘  └───────────┘  └───────────────┘ │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  │  Algorithms: RSA, ECDSA, Ed25519, ML-DSA, ML-KEM (post-quantum)       │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                       │
│  ┌───────────────────────────────────┼───────────────────────────────────┐  │
│  │                       STORAGE LAYER                                    │  │
│  │                                   │                                    │  │
│  │  ┌─────────────┐  ┌─────────────┐ │ ┌─────────────┐  ┌─────────────┐  │  │
│  │  │ PostgreSQL  │  │    LDAP     │ │ │   Redis     │  │    S3       │  │  │
│  │  │ (primary)   │  │ (optional)  │ │ │  (cache)    │  │ (archival)  │  │  │
│  │  └─────────────┘  └─────────────┘ │ └─────────────┘  └─────────────┘  │  │
│  │                                                                        │  │
│  │  ORM: SQLx (compile-time checked queries)                             │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              DEPLOYMENT                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Container  │  │  Kubernetes │  │   Systemd   │  │    Serverless       │ │
│  │  (Docker)   │  │  Operator   │  │  (native)   │  │   (Lambda/etc)      │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                                                                              │
│  Single binary deployment, ~20MB, <100ms startup                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Modular Crate Structure**
   - Separate crates for each subsystem
   - Clear dependency boundaries
   - Independent versioning possible

2. **Async-First**
   - Tokio runtime for async I/O
   - Non-blocking database and HSM operations
   - Efficient resource utilization

3. **Type-Safe Configuration**
   - Compile-time config validation
   - Serde-based serialization
   - Environment variable support

4. **Observable by Default**
   - Structured logging (tracing)
   - Prometheus metrics
   - OpenTelemetry tracing
   - Health check endpoints

5. **Testable Architecture**
   - Trait-based abstractions
   - Mock implementations for testing
   - Property-based testing for crypto

### Storage Architecture: PostgreSQL + Redis

The storage layer uses a dual-database architecture optimized for PKI workloads:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         STORAGE ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    PostgreSQL (Primary Storage)                         ││
│  │                                                                         ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐  ││
│  │  │ Certificates│  │  Requests   │  │ Revocations │  │  Audit Logs   │  ││
│  │  │             │  │             │  │             │  │               │  ││
│  │  │ • Serial #  │  │ • Request ID│  │ • Serial #  │  │ • Timestamp   │  ││
│  │  │ • Subject   │  │ • Status    │  │ • Reason    │  │ • Actor       │  ││
│  │  │ • Issuer    │  │ • Profile   │  │ • Date      │  │ • Action      │  ││
│  │  │ • Validity  │  │ • Requestor │  │ • CRL Entry │  │ • Resource    │  ││
│  │  │ • Extensions│  │ • Device    │  │             │  │ • Details     │  ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────────┘  ││
│  │                                                                         ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐  ││
│  │  │   Profiles  │  │    Users    │  │    Keys     │  │ ACME Accounts │  ││
│  │  │             │  │             │  │   (KRA)     │  │  & Orders     │  ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────────┘  ││
│  │                                                                         ││
│  │  Features: ACID transactions, complex queries, full-text search,       ││
│  │            JSON columns, row-level security, logical replication       ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                      │                                       │
│                          Write-through cache                                 │
│                                      │                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                      Redis (Cache & Fast Layer)                         ││
│  │                                                                         ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐  ││
│  │  │    OCSP     │  │  Sessions   │  │    Rate     │  │  ACME Nonces  │  ││
│  │  │   Cache     │  │  & Tokens   │  │  Limiting   │  │  (short TTL)  │  ││
│  │  │             │  │             │  │             │  │               │  ││
│  │  │ • Signed    │  │ • Auth      │  │ • Per-IP    │  │ • One-time    │  ││
│  │  │   responses │  │   tokens    │  │ • Per-user  │  │   use tokens  │  ││
│  │  │ • 1hr TTL   │  │ • 24hr TTL  │  │ • Sliding   │  │ • 5min TTL    │  ││
│  │  │ • LRU evict │  │             │  │   window    │  │               │  ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────────┘  ││
│  │                                                                         ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐  ││
│  │  │ Distributed │  │   Pub/Sub   │  │   Request   │  │  Health &     │  ││
│  │  │    Locks    │  │  (realtime) │  │   Dedup     │  │  Metrics      │  ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────────┘  ││
│  │                                                                         ││
│  │  Features: Sub-millisecond latency, TTL expiration, pub/sub,           ││
│  │            atomic operations, cluster mode, Lua scripting              ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### PostgreSQL Schema Design

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `certificates` | Issued certificates | serial, subject_dn, issuer_dn, not_before, not_after, status, der_encoded |
| `certificate_requests` | Enrollment requests | request_id, type, status, profile_id, requestor_id, device_type, created_at |
| `revocations` | Revocation records | serial, reason, revoked_at, revoked_by, crl_number |
| `audit_events` | Audit trail | event_id, timestamp, actor, action, resource_type, resource_id, details |
| `profiles` | Certificate profiles | profile_id, name, config_json, enabled, constraints |
| `users` | User accounts | user_id, username, email, groups, created_at |
| `keys` | Archived keys (KRA) | key_id, owner, encrypted_key, algorithm, archived_at |
| `acme_accounts` | ACME accounts | account_id, public_key, contact, status |
| `acme_orders` | ACME orders | order_id, account_id, identifiers, status, expires |
| `webhook_configs` | Webhook settings | webhook_id, url, events, device_types, secret, enabled |

#### Redis Data Structures

| Key Pattern | Type | TTL | Purpose |
|-------------|------|-----|---------|
| `ocsp:{issuer_hash}:{serial}` | String | 1 hour | Cached OCSP response |
| `session:{token}` | Hash | 24 hours | User session data |
| `ratelimit:{ip}:{endpoint}` | String (counter) | 1 minute | Rate limit counter |
| `nonce:{value}` | String | 5 minutes | ACME replay nonce |
| `lock:{resource}` | String | 30 seconds | Distributed lock |
| `dedup:{request_hash}` | String | 5 minutes | Request deduplication |
| `stats:certs:issued` | HyperLogLog | None | Unique cert count |

#### Data Flow Examples

**Certificate Issuance:**
```
1. Request received
2. Check Redis dedup cache → prevent duplicate
3. Validate in application layer
4. BEGIN PostgreSQL transaction
   → Insert certificate_requests
   → Insert certificates
   → Insert audit_events
5. COMMIT transaction
6. Invalidate relevant Redis caches
7. Publish to Redis pub/sub (dashboard update)
```

**OCSP Request:**
```
1. Parse OCSP request
2. Check Redis cache: ocsp:{issuer}:{serial}
   → HIT: Return cached response (sub-ms)
   → MISS: Continue
3. Query PostgreSQL: certificates + revocations
4. Build and sign OCSP response
5. Store in Redis with TTL
6. Return response
```

#### Why This Architecture?

| Requirement | PostgreSQL | Redis |
|-------------|------------|-------|
| **Durability** | ✅ ACID, WAL, replication | ❌ Optional persistence |
| **Complex queries** | ✅ Full SQL | ❌ Key-based only |
| **Audit compliance** | ✅ Immutable history | ❌ Not designed for |
| **Sub-ms latency** | ❌ 1-10ms typical | ✅ <1ms typical |
| **TTL/expiration** | ❌ Manual cleanup | ✅ Native support |
| **Pub/sub** | ⚠️ LISTEN/NOTIFY | ✅ Native, scalable |
| **Horizontal scale** | ⚠️ Read replicas | ✅ Cluster mode |

---

## Component Mapping

### Crate Structure

```
pki-rs/
├── Cargo.toml                    # Workspace definition
├── crates/
│   ├── pki-core/                 # Core types, traits, errors
│   │   ├── src/
│   │   │   ├── types/            # Certificate, Key, Request types
│   │   │   ├── traits/           # CryptoProvider, Storage traits
│   │   │   ├── error.rs          # Error types
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-crypto/               # Cryptography abstraction
│   │   ├── src/
│   │   │   ├── providers/        # Ring, AWS-LC, PKCS#11
│   │   │   ├── algorithms/       # RSA, ECDSA, EdDSA, PQ
│   │   │   ├── x509/             # Certificate operations
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-ca/                   # Certificate Authority
│   │   ├── src/
│   │   │   ├── issuance.rs       # Certificate issuance
│   │   │   ├── renewal.rs        # Certificate renewal
│   │   │   ├── revocation.rs     # Certificate revocation
│   │   │   ├── profiles.rs       # Certificate profiles
│   │   │   ├── policy.rs         # Policy enforcement
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-kra/                  # Key Recovery Authority
│   │   ├── src/
│   │   │   ├── archival.rs       # Key archival
│   │   │   ├── recovery.rs       # Key recovery
│   │   │   ├── escrow.rs         # Key escrow
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-ocsp/                 # OCSP Responder
│   │   ├── src/
│   │   │   ├── responder.rs      # OCSP response generation
│   │   │   ├── cache.rs          # Response caching
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-acme/                 # ACME Protocol
│   │   ├── src/
│   │   │   ├── server.rs         # ACME server
│   │   │   ├── challenges.rs     # HTTP-01, DNS-01
│   │   │   ├── orders.rs         # Order management
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-est/                  # EST Protocol
│   │   ├── src/
│   │   │   ├── enrollment.rs     # Simple enrollment
│   │   │   ├── reenrollment.rs   # Re-enrollment
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-storage/              # Storage backends
│   │   ├── src/
│   │   │   ├── postgres.rs       # PostgreSQL (primary storage)
│   │   │   ├── redis.rs          # Redis (cache layer)
│   │   │   ├── ldap.rs           # LDAP backend (optional)
│   │   │   ├── memory.rs         # In-memory (testing)
│   │   │   ├── traits.rs         # Storage traits
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-cache/                # Caching layer
│   │   ├── src/
│   │   │   ├── ocsp.rs           # OCSP response cache
│   │   │   ├── session.rs        # Session token cache
│   │   │   ├── ratelimit.rs      # Rate limiting
│   │   │   ├── nonce.rs          # ACME nonce management
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-api/                  # REST API
│   │   ├── src/
│   │   │   ├── routes/           # API routes
│   │   │   ├── middleware/       # Auth, logging, etc.
│   │   │   ├── handlers/         # Request handlers
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── pki-notify/               # Notifications
│   │   ├── src/
│   │   │   ├── webhook.rs        # Webhook delivery
│   │   │   ├── kafka.rs          # Kafka producer
│   │   │   ├── rabbitmq.rs       # RabbitMQ publisher
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   └── pki-cli/                  # Command-line tools
│       ├── src/
│       │   ├── main.rs           # CLI entry point
│       │   ├── commands/         # Subcommands
│       │   └── lib.rs
│       └── Cargo.toml
│
├── pki-server/                   # Main server binary
│   ├── src/
│   │   └── main.rs
│   └── Cargo.toml
│
└── tests/                        # Integration tests
    ├── integration/
    └── e2e/
```

### Java to Rust Mapping

| Java Component | Rust Crate | Key Dependencies |
|----------------|------------|------------------|
| `com.netscape.certsrv.*` | `pki-core` | - |
| `com.netscape.cmscore.dbs.*` | `pki-storage` | sqlx, ldap3 |
| `com.netscape.ca.*` | `pki-ca` | pki-crypto, pki-storage |
| `com.netscape.kra.*` | `pki-kra` | pki-crypto, pki-storage |
| `com.netscape.ocsp.*` | `pki-ocsp` | pki-crypto |
| `org.dogtagpki.acme.*` | `pki-acme` | pki-ca |
| `org.dogtagpki.est.*` | `pki-est` | pki-ca |
| `org.dogtagpki.server.rest.*` | `pki-api` | axum, tower |
| `com.netscape.cms.listeners.*` | `pki-notify` | rdkafka, lapin |
| Python CLI tools | `pki-cli` | clap |

### Rust Ecosystem Dependencies

| Purpose | Crate | Description |
|---------|-------|-------------|
| **Async Runtime** | `tokio` | Industry-standard async runtime |
| **HTTP Server** | `axum` | Ergonomic, tower-based web framework |
| **Serialization** | `serde` | Zero-copy serialization |
| **Crypto (default)** | `ring` | High-performance, audited crypto |
| **Crypto (FIPS)** | `aws-lc-rs` | AWS LibCrypto, FIPS 140-3 |
| **X.509** | `x509-cert` | RustCrypto X.509 support |
| **TLS** | `rustls` | Modern TLS implementation |
| **PKCS#11** | `cryptoki` | HSM integration |
| **PostgreSQL** | `sqlx` | Compile-time checked SQL, async |
| **Redis** | `redis` | Async Redis client with connection pooling |
| **LDAP** | `ldap3` | Async LDAP client (optional backend) |
| **Kafka** | `rdkafka` | librdkafka bindings |
| **RabbitMQ** | `lapin` | Pure Rust AMQP |
| **Logging** | `tracing` | Structured, async logging |
| **Metrics** | `metrics` | Prometheus-compatible |
| **CLI** | `clap` | Command-line parsing |
| **Config** | `config` | Layered configuration |
| **Testing** | `proptest` | Property-based testing |
| **Connection Pool** | `deadpool` | Async connection pooling for PostgreSQL/Redis |

---

## Migration Strategy

### Approach: Strangler Fig Pattern

Rather than a big-bang rewrite, use the Strangler Fig pattern:

1. Build new Rust components alongside existing Java
2. Route traffic gradually to Rust services
3. Deprecate Java components as Rust equivalents mature
4. Eventually decommission legacy system

```
Phase 1: Coexistence
┌─────────────────┐     ┌─────────────────┐
│   Load Balancer │     │   Load Balancer │
└────────┬────────┘     └────────┬────────┘
         │                       │
    ┌────┴────┐             ┌────┴────┐
    ▼         ▼             ▼         ▼
┌───────┐ ┌───────┐     ┌───────┐ ┌───────┐
│ Java  │ │ Rust  │     │ Java  │ │ Rust  │
│ CA    │ │ OCSP  │     │ ACME  │ │ ACME  │
│ (old) │ │ (new) │     │ (old) │ │ (new) │
└───────┘ └───────┘     └───────┘ └───────┘
                              │
                        Gradual traffic shift

Phase 2: Rust Primary
┌─────────────────────────────┐
│        Load Balancer        │
└──────────────┬──────────────┘
               │
    ┌──────────┴──────────┐
    ▼                     ▼
┌───────────────┐  ┌────────────┐
│   Rust PKI    │  │  Java PKI  │
│   (primary)   │  │ (fallback) │
│               │  │            │
│ • CA          │  │ Legacy     │
│ • KRA         │  │ features   │
│ • OCSP        │  │ only       │
│ • ACME        │  │            │
│ • EST         │  │            │
└───────────────┘  └────────────┘

Phase 3: Rust Only
┌─────────────────────────────┐
│        Load Balancer        │
└──────────────┬──────────────┘
               │
               ▼
       ┌───────────────┐
       │   Rust PKI    │
       │   (complete)  │
       │               │
       │ All subsystems│
       │ in Rust       │
       └───────────────┘
```

### Migration Order

| Phase | Components | Rationale |
|-------|------------|-----------|
| **1** | OCSP Responder | Simple, stateless, easy to validate |
| **2** | EST Server | Small codebase, clear RFC spec |
| **3** | ACME Server | Well-defined protocol, good test coverage |
| **4** | CLI Tools | Replace Python tools, self-contained |
| **5** | CRL Publisher | Independent, batch-oriented |
| **6** | Certificate Authority | Core functionality, highest complexity |
| **7** | Key Recovery Authority | Security-critical, requires careful audit |
| **8** | TKS/TPS | Token-specific, can remain Java longer |

---

## Risk Assessment

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Crypto library bugs | Low | Critical | Multiple audit cycles, fuzzing, formal verification |
| Performance regression | Medium | High | Benchmark suite, gradual rollout |
| Feature gaps | High | Medium | Prioritize parity, maintain Java fallback |
| HSM compatibility | Medium | High | Extensive hardware testing, PKCS#11 abstraction |
| LDAP compatibility | Medium | Medium | Comprehensive integration tests |

### Organizational Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Rust expertise shortage | High | High | Training program, hire specialists |
| Timeline overrun | High | Medium | Conservative estimates, phased delivery |
| Stakeholder resistance | Medium | Medium | Clear communication, demonstrate value early |
| Parallel maintenance burden | High | Medium | Automate testing, shared test suites |

### Compliance Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| FIPS 140-3 certification | Medium | Critical | Use aws-lc-rs with FIPS module |
| Common Criteria | Medium | High | Engage evaluation lab early |
| Audit trail gaps | Low | High | Ensure audit logging parity |

---

## Timeline & Phases

### Phase 1: Foundation (Months 1-6)

**Objective**: Establish project structure, core types, and first production component

| Milestone | Deliverable | Duration |
|-----------|-------------|----------|
| 1.1 | Project setup, CI/CD, dev environment | 1 month |
| 1.2 | Core types and traits (`pki-core`) | 1 month |
| 1.3 | Crypto abstraction layer (`pki-crypto`) | 2 months |
| 1.4 | OCSP Responder (`pki-ocsp`) | 2 months |

**Exit Criteria**:
- OCSP responder passing all integration tests
- Performance equal or better than Java
- Security audit completed

---

### Phase 2: Protocol Servers (Months 7-14)

**Objective**: Migrate automated enrollment protocols

| Milestone | Deliverable | Duration |
|-----------|-------------|----------|
| 2.1 | Storage abstraction (`pki-storage`) | 2 months |
| 2.2 | EST Server (`pki-est`) | 2 months |
| 2.3 | ACME Server (`pki-acme`) | 3 months |
| 2.4 | CLI tools (`pki-cli`) | 1 month |

**Exit Criteria**:
- EST/ACME servers production-ready
- CLI tools replace Python equivalents
- Interoperability testing complete

---

### Phase 3: Core CA (Months 15-26)

**Objective**: Migrate Certificate Authority core

| Milestone | Deliverable | Duration |
|-----------|-------------|----------|
| 3.1 | Profile engine | 3 months |
| 3.2 | Certificate issuance | 3 months |
| 3.3 | Renewal and revocation | 2 months |
| 3.4 | CRL generation and publishing | 2 months |
| 3.5 | Notification system (`pki-notify`) | 2 months |

**Exit Criteria**:
- CA feature parity with Java version
- Performance benchmarks met
- Security audit completed
- FIPS certification initiated

---

### Phase 4: Key Management (Months 27-36)

**Objective**: Migrate KRA and complete system

| Milestone | Deliverable | Duration |
|-----------|-------------|----------|
| 4.1 | Key archival | 3 months |
| 4.2 | Key recovery | 3 months |
| 4.3 | REST API consolidation | 2 months |
| 4.4 | Admin UI | 2 months |

**Exit Criteria**:
- Full feature parity
- All integration tests passing
- FIPS certification complete
- Java system decommissioned

---

### Summary Timeline

```
Year 1                    Year 2                    Year 3
├─────────────────────────┼─────────────────────────┼─────────────────────────┤
│ Phase 1    │ Phase 2    │ Phase 3                 │ Phase 4                 │
│ Foundation │ Protocols  │ Core CA                 │ Key Management          │
│            │            │                         │                         │
│ • Core     │ • EST      │ • Profiles              │ • KRA                   │
│ • Crypto   │ • ACME     │ • Issuance              │ • REST API              │
│ • OCSP     │ • CLI      │ • Revocation            │ • Admin UI              │
│            │            │ • CRL                   │ • Decommission Java     │
│            │            │ • Notifications         │                         │
├────────────┴────────────┴─────────────────────────┴─────────────────────────┤
│                                                                              │
│  ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
│  Phase 1                                                                     │
│                                                                              │
│  ░░░░░░░░████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
│          Phase 2                                                             │
│                                                                              │
│  ░░░░░░░░░░░░░░░░░░░░░░░░████████████████████████████░░░░░░░░░░░░░░░░░░░░░ │
│                          Phase 3                                             │
│                                                                              │
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████████████████░ │
│                                                      Phase 4                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Resource Requirements

### Team Structure

| Role | Count | Responsibilities |
|------|-------|------------------|
| Technical Lead | 1 | Architecture, decisions, code review |
| Senior Rust Engineers | 3-4 | Core implementation |
| Rust Engineers | 2-3 | Feature development, testing |
| Security Engineer | 1 | Crypto review, auditing |
| DevOps Engineer | 1 | CI/CD, deployment, infrastructure |
| QA Engineer | 1-2 | Test automation, validation |
| Technical Writer | 0.5 | Documentation |

### Infrastructure

| Resource | Purpose |
|----------|---------|
| CI/CD pipeline | Build, test, deploy automation |
| HSM test devices | Hardware security module testing |
| Cloud environments | AWS/GCP for testing at scale |
| Security scanning | Fuzzing, SAST, dependency scanning |

### External Resources

| Resource | Purpose | Estimated Cost |
|----------|---------|----------------|
| Security audit (per component) | Third-party code audit | $50-100K each |
| FIPS 140-3 certification | Compliance | $200-500K |
| Rust training | Team upskilling | $50-100K |
| Consulting | Architecture review | $50-100K |

---

## Success Criteria

### Technical Metrics

| Metric | Target |
|--------|--------|
| Memory safety vulnerabilities | 0 (enforced by Rust) |
| Performance vs Java | Equal or better |
| Binary size | < 50MB |
| Startup time | < 1 second |
| Memory usage | < 50% of Java |
| Test coverage | > 80% |

### Operational Metrics

| Metric | Target |
|--------|--------|
| API compatibility | 100% (existing clients work) |
| Migration downtime | Zero (parallel operation) |
| Feature parity | 100% before Java decommission |
| FIPS certification | Achieved |

### Project Metrics

| Metric | Target |
|--------|--------|
| Timeline adherence | Within 20% |
| Budget adherence | Within 15% |
| Team satisfaction | > 4/5 |
| Stakeholder approval | Signed off at each phase |

---

## Appendix: Technology Decisions

### Why Not Go?

Go was considered but rejected because:
- Garbage collection can cause latency spikes during HSM operations
- Less expressive type system (no generics until recently)
- Error handling less robust than Rust's Result type
- Crypto ecosystem less mature

### Why Not Keep Java?

Java could remain, but:
- Native components (NSS/JSS) remain unsafe
- JVM overhead for cloud-native deployments
- Slower startup times
- Higher memory footprint
- Dependency on aging libraries

### Post-Quantum Readiness

The Rust crypto ecosystem is preparing for post-quantum:
- `pqcrypto` crate family
- ML-DSA (Dilithium) implementations
- ML-KEM (Kyber) implementations
- Hybrid signature schemes

This rewrite positions PKI-RS for post-quantum migration.

---

## Conclusion

Rewriting Dogtag PKI in Rust is a significant investment that will deliver:

1. **Complete memory safety** - Eliminate entire vulnerability classes
2. **Modern architecture** - Cloud-native, async, observable
3. **Better performance** - Lower latency, less memory
4. **Future-proof** - Post-quantum ready, active ecosystem
5. **Operational simplicity** - Single binary, fast startup

The phased approach minimizes risk while delivering value incrementally. Starting with OCSP provides a low-risk proof of concept, building confidence for larger components.

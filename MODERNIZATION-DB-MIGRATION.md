# Database Migration Strategy: LDAP to PostgreSQL

## 4. Database Migration Strategy

### 4.1 Migration Overview

**Goal:** Transition from LDAP-centric storage to a hybrid model supporting both LDAP and PostgreSQL, with PostgreSQL as the primary datastore for new deployments.

**Strategy:** Phased migration with backward compatibility

**Timeline:** 12-18 months

### 4.2 Current LDAP Schema Analysis

#### 4.2.1 LDAP Directory Structure

```
dc=pki,dc=example,dc=com
├── ou=certificateRepository,ou=ca
│   ├── cn=1 (certificate record)
│   ├── cn=2
│   └── ...
├── ou=requests,ou=ca
│   ├── cn=1 (request record)
│   └── ...
├── ou=crlRepository,ou=ca
│   ├── cn=1 (CRL record)
│   └── ...
├── ou=keyRepository,ou=kra
│   ├── cn=1 (key record)
│   └── ...
└── ou=config
    └── cn=CS.cfg
```

#### 4.2.2 Key LDAP Object Classes

**Certificate Records:**
```ldif
dn: cn=1,ou=certificateRepository,ou=ca,dc=pki,dc=example,dc=com
objectClass: top
objectClass: certificateRecord
cn: 1
serialno: 1
subjectName: CN=Example,O=Dogtag
issuerName: CN=CA Signing Certificate,O=Dogtag
notBefore: 20260114120000Z
notAfter: 20280114120000Z
userCertificate:: MIIDXzCCAke...  (DER-encoded cert)
certStatus: VALID
```

**Request Records:**
```ldif
dn: cn=1,ou=requests,ou=ca,dc=pki,dc=example,dc=com
objectClass: top
objectClass: requestRecord
cn: 1
requestId: 1
requestType: enrollment
requestState: complete
requestOwner: admin
requestCreationTime: 20260114120000Z
requestModificationTime: 20260114120100Z
extData: {JSON-encoded request data}
```

**Key Records (KRA):**
```ldif
dn: cn=1,ou=keyRepository,ou=kra,dc=pki,dc=example,dc=com
objectClass: top
objectClass: keyRecord
cn: 1
serialno: 1
ownerName: CN=Example,O=Dogtag
privateKeyData:: {encrypted key}
publicKeyData:: {public key}
dateOfCreate: 20260114120000Z
```

### 4.3 Target PostgreSQL Schema

#### 4.3.1 Relational Schema Design

```sql
-- Database: pki_ca

-- Certificates table
CREATE TABLE certificates (
    id BIGSERIAL PRIMARY KEY,
    serial_number VARCHAR(64) UNIQUE NOT NULL,
    subject_dn TEXT NOT NULL,
    issuer_dn TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL,
    revocation_reason VARCHAR(50),
    revoked_on TIMESTAMPTZ,
    revoked_by VARCHAR(255),
    der_encoding BYTEA NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_cert_serial ON certificates(serial_number);
CREATE INDEX idx_cert_subject ON certificates USING GIN(to_tsvector('english', subject_dn));
CREATE INDEX idx_cert_issuer ON certificates(issuer_dn);
CREATE INDEX idx_cert_status ON certificates(status) WHERE status != 'VALID';
CREATE INDEX idx_cert_expiry ON certificates(not_after) WHERE status = 'VALID';
CREATE INDEX idx_cert_metadata ON certificates USING GIN(metadata);

-- Certificate requests table
CREATE TABLE cert_requests (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(64) UNIQUE NOT NULL,
    request_type VARCHAR(50) NOT NULL,
    request_status VARCHAR(50) NOT NULL,
    profile_id VARCHAR(255),
    subject_dn TEXT,
    csr TEXT,
    issued_cert_serial VARCHAR(64),
    requestor_id VARCHAR(255) NOT NULL,
    request_data JSONB,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_request_id ON cert_requests(request_id);
CREATE INDEX idx_request_status ON cert_requests(request_status);
CREATE INDEX idx_request_requestor ON cert_requests(requestor_id);
CREATE INDEX idx_request_created ON cert_requests(created_at DESC);

-- Certificate Revocation Lists
CREATE TABLE crls (
    id BIGSERIAL PRIMARY KEY,
    crl_number BIGINT UNIQUE NOT NULL,
    issuer_dn TEXT NOT NULL,
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL,
    der_encoding BYTEA NOT NULL,
    revoked_certs JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_crl_number ON crls(crl_number DESC);
CREATE INDEX idx_crl_next_update ON crls(next_update);

-- Key records (KRA)
CREATE TABLE key_records (
    id BIGSERIAL PRIMARY KEY,
    key_id VARCHAR(64) UNIQUE NOT NULL,
    owner_dn TEXT NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    key_size INTEGER,
    private_key_data BYTEA NOT NULL, -- encrypted
    public_key_data BYTEA,
    cert_serial VARCHAR(64),
    status VARCHAR(20) NOT NULL,
    date_of_create TIMESTAMPTZ NOT NULL,
    date_of_recovery TIMESTAMPTZ,
    metadata JSONB
);

CREATE INDEX idx_key_id ON key_records(key_id);
CREATE INDEX idx_key_owner ON key_records(owner_dn);
CREATE INDEX idx_key_cert_serial ON key_records(cert_serial);

-- Audit logs (immutable)
CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    event_status VARCHAR(20) NOT NULL,
    subject_id VARCHAR(255),
    outcome VARCHAR(20) NOT NULL,
    event_data JSONB NOT NULL,
    client_ip INET,
    server_ip INET,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_type ON audit_events(event_type);
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_subject ON audit_events(subject_id);

-- Partitioning for audit logs (by month)
CREATE TABLE audit_events_y2026m01 PARTITION OF audit_events
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
-- ... create partitions for each month

-- Profiles
CREATE TABLE profiles (
    id BIGSERIAL PRIMARY KEY,
    profile_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    visible BOOLEAN NOT NULL DEFAULT true,
    config JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_profile_id ON profiles(profile_id);
CREATE INDEX idx_profile_enabled ON profiles(enabled) WHERE enabled = true;
```

#### 4.3.2 Data Type Mapping

| LDAP Attribute | LDAP Type | PostgreSQL Column | PostgreSQL Type |
|----------------|-----------|-------------------|-----------------|
| serialno | String | serial_number | VARCHAR(64) |
| subjectName | DN String | subject_dn | TEXT |
| notBefore | GeneralizedTime | not_before | TIMESTAMPTZ |
| userCertificate | Binary | der_encoding | BYTEA |
| certStatus | String | status | VARCHAR(20) + ENUM |
| extData | String (JSON) | metadata/request_data | JSONB |
| requestId | String | request_id | VARCHAR(64) |

### 4.4 Migration Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Application Layer                      │
│           (CA/KRA/OCSP Services)                        │
└───────────────────┬─────────────────────────────────────┘
                    │
            ┌───────▼────────┐
            │ Repository     │
            │ Abstraction    │
            │ Layer          │
            └───────┬────────┘
                    │
        ┌───────────┼───────────┐
        │                       │
┌───────▼─────────┐    ┌───────▼─────────┐
│ LDAP Repository │    │ PostgreSQL      │
│ (Legacy)        │    │ Repository      │
└───────┬─────────┘    └───────┬─────────┘
        │                       │
┌───────▼─────────┐    ┌───────▼─────────┐
│ 389 Directory   │    │ PostgreSQL      │
│ Server          │    │ Cluster         │
└─────────────────┘    └─────────────────┘
        │                       │
        └───────────┬───────────┘
                    │
            ┌───────▼────────┐
            │ Sync Service   │
            │ (Bidirectional)│
            └────────────────┘
```

### 4.5 Migration Phases

#### Phase 1: Abstraction Layer (Months 1-3)

**Goal:** Create repository abstraction to support multiple backends

```java
// Repository interface
package org.dogtagpki.server.repository;

public interface CertificateRepository {
    Uni<Certificate> save(Certificate cert);
    Uni<Certificate> findBySerialNumber(String serialNumber);
    Uni<List<Certificate>> findBySubjectDN(String subjectDN);
    Uni<Long> count();
    Uni<Void> update(Certificate cert);
}

// LDAP implementation (existing)
@ApplicationScoped
@Named("ldap")
public class LDAPCertificateRepository implements CertificateRepository {

    @Inject
    LDAPConnection ldapConn;

    @Override
    public Uni<Certificate> findBySerialNumber(String serialNumber) {
        return Uni.createFrom().item(() -> {
            String dn = String.format("cn=%s,ou=certificateRepository,ou=ca,%s",
                serialNumber, baseDN);

            SearchResult result = ldapConn.search(dn, SearchScope.BASE, "(objectClass=*)");

            if (result.getEntryCount() == 0) {
                return null;
            }

            return mapLDAPToCertificate(result.getSearchEntries().get(0));
        });
    }

    private Certificate mapLDAPToCertificate(SearchResultEntry entry) {
        Certificate cert = new Certificate();
        cert.serialNumber = entry.getAttributeValue("serialno");
        cert.subjectDN = entry.getAttributeValue("subjectName");
        cert.issuerDN = entry.getAttributeValue("issuerName");
        cert.notBefore = parseGeneralizedTime(entry.getAttributeValue("notBefore"));
        cert.notAfter = parseGeneralizedTime(entry.getAttributeValue("notAfter"));
        cert.status = CertificateStatus.valueOf(entry.getAttributeValue("certStatus"));
        cert.derEncoding = entry.getAttributeValueBytes("userCertificate");
        return cert;
    }
}

// PostgreSQL implementation (new)
@ApplicationScoped
@Named("postgresql")
public class PostgreSQLCertificateRepository implements CertificateRepository {

    @Inject
    PgPool pgPool;

    @Override
    public Uni<Certificate> findBySerialNumber(String serialNumber) {
        return pgPool.preparedQuery(
            "SELECT * FROM certificates WHERE serial_number = $1"
        )
        .execute(Tuple.of(serialNumber))
        .onItem().transform(rowSet -> {
            if (!rowSet.iterator().hasNext()) {
                return null;
            }
            return mapRowToCertificate(rowSet.iterator().next());
        });
    }

    private Certificate mapRowToCertificate(Row row) {
        Certificate cert = new Certificate();
        cert.id = row.getLong("id");
        cert.serialNumber = row.getString("serial_number");
        cert.subjectDN = row.getString("subject_dn");
        cert.issuerDN = row.getString("issuer_dn");
        cert.notBefore = row.getOffsetDateTime("not_before").toInstant();
        cert.notAfter = row.getOffsetDateTime("not_after").toInstant();
        cert.status = CertificateStatus.valueOf(row.getString("status"));
        cert.derEncoding = row.getBuffer("der_encoding").getBytes();
        return cert;
    }
}

// Service layer uses abstraction
@ApplicationScoped
public class CertificateService {

    @Inject
    @ConfigProperty(name = "pki.repository.backend", defaultValue = "ldap")
    String repositoryBackend;

    @Inject
    @Named("ldap")
    CertificateRepository ldapRepo;

    @Inject
    @Named("postgresql")
    CertificateRepository pgRepo;

    private CertificateRepository getRepository() {
        return "postgresql".equals(repositoryBackend) ? pgRepo : ldapRepo;
    }

    public Uni<Certificate> getCertificate(String serialNumber) {
        return getRepository().findBySerialNumber(serialNumber);
    }
}
```

#### Phase 2: Dual-Write Mode (Months 4-8)

**Goal:** Write to both LDAP and PostgreSQL simultaneously

```java
@ApplicationScoped
@Named("dual")
public class DualWriteCertificateRepository implements CertificateRepository {

    @Inject
    @Named("ldap")
    CertificateRepository ldapRepo;

    @Inject
    @Named("postgresql")
    CertificateRepository pgRepo;

    @Inject
    @ConfigProperty(name = "pki.repository.primary", defaultValue = "ldap")
    String primaryBackend;

    @Override
    public Uni<Certificate> save(Certificate cert) {
        // Write to both backends
        Uni<Certificate> ldapWrite = ldapRepo.save(cert)
            .onFailure().invoke(e -> LOG.error("LDAP write failed", e));

        Uni<Certificate> pgWrite = pgRepo.save(cert)
            .onFailure().invoke(e -> LOG.error("PostgreSQL write failed", e));

        // Return result from primary
        if ("postgresql".equals(primaryBackend)) {
            return pgWrite.onItem().invoke(() -> ldapWrite.subscribe().with(r -> {}));
        } else {
            return ldapWrite.onItem().invoke(() -> pgWrite.subscribe().with(r -> {}));
        }
    }

    @Override
    public Uni<Certificate> findBySerialNumber(String serialNumber) {
        // Read from primary only
        return "postgresql".equals(primaryBackend)
            ? pgRepo.findBySerialNumber(serialNumber)
            : ldapRepo.findBySerialNumber(serialNumber);
    }
}
```

#### Phase 3: Data Migration (Months 6-12)

**Goal:** Migrate existing LDAP data to PostgreSQL

##### 4.5.1 Migration Tool

```java
package org.dogtagpki.tools.migration;

@ApplicationScoped
public class LDAPToPostgreSQLMigrator {

    @Inject
    @Named("ldap")
    CertificateRepository ldapRepo;

    @Inject
    @Named("postgresql")
    CertificateRepository pgRepo;

    @Inject
    MigrationMetrics metrics;

    public Uni<MigrationResult> migrateCertificates(MigrationOptions options) {
        LOG.info("Starting certificate migration");

        return ldapRepo.findAll(options.batchSize, options.offset)
            .onItem().transformToMulti(certs -> Multi.createFrom().iterable(certs))
            .onItem().transformToUniAndConcatenate(cert ->
                pgRepo.save(cert)
                    .onItem().invoke(() -> metrics.incrementMigrated())
                    .onFailure().invoke(e -> {
                        LOG.error("Failed to migrate cert: " + cert.serialNumber, e);
                        metrics.incrementFailed();
                    })
                    .onFailure().recoverWithNull()
            )
            .collect().asList()
            .map(results -> new MigrationResult(
                metrics.getMigrated(),
                metrics.getFailed()
            ));
    }

    public record MigrationOptions(
        int batchSize,
        int offset,
        boolean verifyAfterMigration
    ) {}

    public record MigrationResult(
        long migrated,
        long failed
    ) {}
}

// CLI tool
@QuarkusMain
public class MigrationCLI implements QuarkusApplication {

    @Inject
    LDAPToPostgreSQLMigrator migrator;

    @Override
    public int run(String... args) {
        CommandLine cmd = new CommandLine(new MigrationCommand());
        return cmd.execute(args);
    }

    @Command(name = "migrate")
    static class MigrationCommand implements Callable<Integer> {

        @Option(names = {"-b", "--batch-size"}, defaultValue = "1000")
        int batchSize;

        @Option(names = {"-o", "--offset"}, defaultValue = "0")
        int offset;

        @Option(names = {"--verify"}, defaultValue = "true")
        boolean verify;

        @Override
        public Integer call() {
            System.out.println("Starting migration...");

            MigrationResult result = migrator.migrateCertificates(
                new MigrationOptions(batchSize, offset, verify)
            ).await().indefinitely();

            System.out.printf("Migration complete: %d migrated, %d failed%n",
                result.migrated(), result.failed());

            return result.failed() > 0 ? 1 : 0;
        }
    }
}
```

##### 4.5.2 Migration Script

```bash
#!/bin/bash
# migrate-to-postgresql.sh

set -e

BATCH_SIZE=1000
TOTAL_CERTS=$(ldapsearch -x -b "ou=certificateRepository,ou=ca,dc=pki,dc=example,dc=com" \
              "(objectClass=certificateRecord)" dn | grep -c "^dn:")

echo "Total certificates to migrate: $TOTAL_CERTS"

for ((offset=0; offset<TOTAL_CERTS; offset+=BATCH_SIZE)); do
    echo "Migrating batch: offset=$offset, size=$BATCH_SIZE"

    java -jar migration-tool.jar migrate \
        --batch-size $BATCH_SIZE \
        --offset $offset \
        --verify

    if [ $? -ne 0 ]; then
        echo "Migration failed at offset $offset"
        exit 1
    fi

    echo "Progress: $((offset + BATCH_SIZE))/$TOTAL_CERTS"
done

echo "Migration completed successfully!"
```

#### Phase 4: Verification & Reconciliation (Months 10-14)

**Goal:** Verify data consistency between backends

```java
@ApplicationScoped
public class DataConsistencyChecker {

    @Inject
    @Named("ldap")
    CertificateRepository ldapRepo;

    @Inject
    @Named("postgresql")
    CertificateRepository pgRepo;

    public Uni<ConsistencyReport> verifyConsistency() {
        return Uni.combine().all()
            .unis(
                ldapRepo.count(),
                pgRepo.count()
            )
            .asTuple()
            .flatMap(counts -> {
                long ldapCount = counts.getItem1();
                long pgCount = counts.getItem2();

                if (ldapCount != pgCount) {
                    LOG.warn("Count mismatch: LDAP={}, PostgreSQL={}", ldapCount, pgCount);
                }

                return verifyIndividualRecords(ldapCount, pgCount);
            });
    }

    private Uni<ConsistencyReport> verifyIndividualRecords(long ldapCount, long pgCount) {
        // Sample-based verification
        int sampleSize = Math.min(10000, (int)(ldapCount * 0.01)); // 1% sample

        return ldapRepo.findRandomSample(sampleSize)
            .onItem().transformToMulti(certs -> Multi.createFrom().iterable(certs))
            .onItem().transformToUniAndConcatenate(ldapCert ->
                pgRepo.findBySerialNumber(ldapCert.serialNumber)
                    .map(pgCert -> compareCertificates(ldapCert, pgCert))
            )
            .collect().asList()
            .map(results -> new ConsistencyReport(
                ldapCount,
                pgCount,
                results.stream().filter(r -> !r.consistent).count(),
                results
            ));
    }

    private ComparisonResult compareCertificates(Certificate ldapCert, Certificate pgCert) {
        if (pgCert == null) {
            return new ComparisonResult(ldapCert.serialNumber, false, "Missing in PostgreSQL");
        }

        List<String> differences = new ArrayList<>();

        if (!ldapCert.subjectDN.equals(pgCert.subjectDN)) {
            differences.add("subjectDN mismatch");
        }
        if (!Arrays.equals(ldapCert.derEncoding, pgCert.derEncoding)) {
            differences.add("DER encoding mismatch");
        }
        if (ldapCert.status != pgCert.status) {
            differences.add("status mismatch");
        }

        return new ComparisonResult(
            ldapCert.serialNumber,
            differences.isEmpty(),
            String.join(", ", differences)
        );
    }

    public record ConsistencyReport(
        long ldapCount,
        long postgresqlCount,
        long inconsistencies,
        List<ComparisonResult> results
    ) {}

    public record ComparisonResult(
        String serialNumber,
        boolean consistent,
        String details
    ) {}
}
```

#### Phase 5: PostgreSQL-First Mode (Months 14-18)

**Goal:** Switch to PostgreSQL as primary, LDAP as backup

```properties
# application.properties

# Phase 5: PostgreSQL primary
pki.repository.backend=dual
pki.repository.primary=postgresql
pki.repository.secondary=ldap
pki.repository.sync-mode=async
```

#### Phase 6: LDAP Deprecation (Month 18+)

**Goal:** LDAP becomes optional for legacy support only

```properties
# application.properties

# Phase 6: PostgreSQL only (LDAP optional)
pki.repository.backend=postgresql
pki.repository.ldap.enabled=false
```

### 4.6 Rollback Strategy

At each phase, maintain ability to rollback:

1. **Phase 1-2:** No data loss, switch backend config
2. **Phase 3-4:** Stop dual-write, continue LDAP-only
3. **Phase 5:** Switch primary back to LDAP
4. **Phase 6:** Re-enable dual-write mode

```bash
# Rollback script
#!/bin/bash

echo "Rolling back to LDAP-only mode"

kubectl patch configmap ca-config -p '{"data":{"application.properties":"pki.repository.backend=ldap"}}'
kubectl rollout restart deployment/ca-service

echo "Rollback complete"
```

### 4.7 Performance Optimization

#### 4.7.1 Indexing Strategy

```sql
-- Covering index for common queries
CREATE INDEX idx_cert_lookup ON certificates(serial_number, status, not_after)
    INCLUDE (subject_dn, issuer_dn);

-- Partial index for active certificates
CREATE INDEX idx_cert_active ON certificates(not_after)
    WHERE status = 'VALID';

-- GIN index for full-text search
CREATE INDEX idx_cert_subject_fts ON certificates
    USING GIN(to_tsvector('english', subject_dn));
```

#### 4.7.2 Connection Pooling

```properties
# application.properties

quarkus.datasource.reactive.max-size=50
quarkus.datasource.reactive.idle-timeout=10m
quarkus.datasource.reactive.max-lifetime=30m
quarkus.datasource.reactive.pool-cleaner-period=5m
```

### 4.8 Migration Checklist

- [ ] Create repository abstraction layer
- [ ] Implement PostgreSQL repository
- [ ] Create database schema and indexes
- [ ] Implement dual-write mode
- [ ] Develop migration tool
- [ ] Perform test migration (dev environment)
- [ ] Verify data consistency
- [ ] Performance testing (both backends)
- [ ] Create rollback procedures
- [ ] Document migration process
- [ ] Train operations team
- [ ] Execute production migration
- [ ] Monitor for 30 days in dual-write
- [ ] Switch to PostgreSQL-primary
- [ ] Deprecate LDAP (optional)

### 4.9 Success Metrics

- **Data Integrity:** 100% consistency between backends
- **Performance:** PostgreSQL queries 3-5x faster than LDAP
- **Reliability:** 99.99% uptime during migration
- **Zero Data Loss:** Complete audit trail of migration
- **Backward Compatibility:** Existing deployments continue to work

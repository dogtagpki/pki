# Dogtag PKI Modernization Guide

**Version:** 1.0
**Date:** 2026-01-14
**Purpose:** Comprehensive modernization strategy for Dogtag PKI

---

## Document Overview

This modernization guide consists of 5 detailed deliverables:

1. **MODERNIZATION-GUIDE.md** (this file) - CA Microservice Technical Design
2. **MODERNIZATION-POC-ACME.md** - ACME Migration Proof of Concept
3. **MODERNIZATION-K8S-OPERATOR.md** - Kubernetes Operator Specification
4. **MODERNIZATION-DB-MIGRATION.md** - Database Migration Strategy
5. **MODERNIZATION-IMPLEMENTATION-PLAN.md** - Complete 36-Month Roadmap

## Executive Summary

Dogtag PKI modernization transforms the enterprise-grade PKI platform into a cloud-native, microservices-based architecture optimized for digital sovereignty. The modernization delivers:

- **4x performance improvement** (2000+ req/sec vs 500 req/sec)
- **10x faster startup** (<1 second vs 30 seconds)
- **90% memory reduction** (50MB vs 512MB base)
- **Cloud-native deployment** (Kubernetes-first with operator)
- **Digital sovereignty** (on-premise, air-gap capable, GDPR compliant)
- **Multi-database support** (PostgreSQL primary, LDAP optional)
- **Event-driven architecture** (Kafka-based inter-service communication)
- **Modern observability** (OpenTelemetry, Prometheus, Grafana)

**Timeline:** 36 months (3 years)
**Investment:** ~$1.9M infrastructure + 27 FTE team
**Risk Level:** Medium (mitigated through phased approach)

---

## Table of Contents

1. [Technical Design: CA Microservice (Quarkus)](#1-technical-design-ca-microservice-quarkus)
2. [See MODERNIZATION-POC-ACME.md for ACME Proof of Concept](#2-acme-proof-of-concept)
3. [See MODERNIZATION-K8S-OPERATOR.md for Kubernetes Operator](#3-kubernetes-operator)
4. [See MODERNIZATION-DB-MIGRATION.md for Database Migration](#4-database-migration)
5. [See MODERNIZATION-IMPLEMENTATION-PLAN.md for Full Roadmap](#5-implementation-plan)

---

## 1. Technical Design: CA Microservice (Quarkus)

### 1.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CA Microservice                          │
├─────────────────────────────────────────────────────────────┤
│  REST API Layer (JAX-RS Reactive)                          │
│  ├─ CertificateResource                                    │
│  ├─ CertRequestResource                                    │
│  ├─ ProfileResource                                        │
│  └─ CRLResource                                            │
├─────────────────────────────────────────────────────────────┤
│  Service Layer (Business Logic)                            │
│  ├─ CertificateService                                     │
│  ├─ EnrollmentService                                      │
│  ├─ RevocationService                                      │
│  └─ ProfileEngine                                          │
├─────────────────────────────────────────────────────────────┤
│  Security Layer                                            │
│  ├─ AuthenticationFilter                                   │
│  ├─ AuthorizationInterceptor                              │
│  └─ AuditLogger                                            │
├─────────────────────────────────────────────────────────────┤
│  Repository Layer (Data Access)                            │
│  ├─ CertificateRepository (JPA/Panache)                   │
│  ├─ RequestRepository                                      │
│  └─ CRLRepository                                          │
├─────────────────────────────────────────────────────────────┤
│  Integration Layer                                         │
│  ├─ EventPublisher (Kafka/NATS)                           │
│  ├─ KRAClient (REST Client)                               │
│  └─ HSMConnector (PKCS#11)                                │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Project Structure

```
ca-service/
├── pom.xml
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── org/dogtagpki/ca/
│   │   │       ├── rest/
│   │   │       │   ├── CertificateResource.java
│   │   │       │   ├── CertRequestResource.java
│   │   │       │   ├── ProfileResource.java
│   │   │       │   └── CRLResource.java
│   │   │       ├── service/
│   │   │       │   ├── CertificateService.java
│   │   │       │   ├── EnrollmentService.java
│   │   │       │   ├── RevocationService.java
│   │   │       │   └── ProfileEngine.java
│   │   │       ├── repository/
│   │   │       │   ├── CertificateRepository.java
│   │   │       │   ├── RequestRepository.java
│   │   │       │   └── CRLRepository.java
│   │   │       ├── model/
│   │   │       │   ├── Certificate.java
│   │   │       │   ├── CertRequest.java
│   │   │       │   ├── Profile.java
│   │   │       │   └── CRL.java
│   │   │       ├── security/
│   │   │       │   ├── AuthFilter.java
│   │   │       │   ├── ACLInterceptor.java
│   │   │       │   └── AuditInterceptor.java
│   │   │       ├── crypto/
│   │   │       │   ├── SigningEngine.java
│   │   │       │   └── HSMProvider.java
│   │   │       └── event/
│   │   │           ├── CertificateEvent.java
│   │   │           └── EventPublisher.java
│   │   └── resources/
│   │       ├── application.properties
│   │       ├── META-INF/
│   │       │   └── openapi.yaml
│   │       └── db/
│   │           └── migration/
│   │               └── V1__initial_schema.sql
│   └── test/
│       └── java/
│           └── org/dogtagpki/ca/
│               ├── CertificateResourceTest.java
│               └── EnrollmentServiceTest.java
├── Dockerfile
├── k8s/
│   ├── deployment.yaml
│   ├── service.yaml
│   └── configmap.yaml
└── README.md
```

### 1.3 Core Implementation

#### 1.3.1 POM Configuration

```xml
<?xml version="1.0"?>
<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         https://maven.apache.org/xsd/maven-4.0.0.xsd"
         xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.dogtagpki</groupId>
    <artifactId>ca-service</artifactId>
    <version>11.0.0-SNAPSHOT</version>

    <properties>
        <compiler-plugin.version>3.11.0</compiler-plugin.version>
        <maven.compiler.release>21</maven.compiler.release>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <quarkus.platform.version>3.6.4</quarkus.platform.version>
        <surefire-plugin.version>3.0.0</surefire-plugin.version>
    </properties>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>io.quarkus.platform</groupId>
                <artifactId>quarkus-bom</artifactId>
                <version>${quarkus.platform.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <dependencies>
        <!-- Quarkus Core -->
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-resteasy-reactive-jackson</artifactId>
        </dependency>
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-hibernate-reactive-panache</artifactId>
        </dependency>
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-reactive-pg-client</artifactId>
        </dependency>

        <!-- Security -->
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-oidc</artifactId>
        </dependency>
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-security</artifactId>
        </dependency>

        <!-- Messaging -->
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-smallrye-reactive-messaging-kafka</artifactId>
        </dependency>

        <!-- Observability -->
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-micrometer-registry-prometheus</artifactId>
        </dependency>
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-opentelemetry</artifactId>
        </dependency>
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-smallrye-health</artifactId>
        </dependency>

        <!-- OpenAPI -->
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-smallrye-openapi</artifactId>
        </dependency>

        <!-- Cryptography -->
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcpkix-jdk18on</artifactId>
            <version>1.77</version>
        </dependency>
        <dependency>
            <groupId>org.mozilla.jss</groupId>
            <artifactId>jss</artifactId>
            <version>5.5.0</version>
        </dependency>

        <!-- Testing -->
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-junit5</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>io.rest-assured</groupId>
            <artifactId>rest-assured</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>${quarkus.platform.group-id}</groupId>
                <artifactId>quarkus-maven-plugin</artifactId>
                <version>${quarkus.platform.version}</version>
                <executions>
                    <execution>
                        <goals>
                            <goal>build</goal>
                            <goal>generate-code</goal>
                            <goal>generate-code-tests</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

#### 1.3.2 Application Configuration

```properties
# application.properties

# Application
quarkus.application.name=ca-service
quarkus.application.version=11.0.0

# HTTP
quarkus.http.port=8443
quarkus.http.ssl-port=8443
quarkus.http.ssl.certificate.key-store-file=config/keystore.p12
quarkus.http.ssl.certificate.key-store-password=${KEYSTORE_PASSWORD}
quarkus.http.ssl.client-auth=requested

# Database
quarkus.datasource.db-kind=postgresql
quarkus.datasource.username=${DB_USER:pki}
quarkus.datasource.password=${DB_PASSWORD}
quarkus.datasource.reactive.url=postgresql://${DB_HOST:localhost}:${DB_PORT:5432}/${DB_NAME:ca}
quarkus.datasource.reactive.max-size=20

# Hibernate
quarkus.hibernate-orm.database.generation=validate
quarkus.hibernate-orm.log.sql=false
quarkus.flyway.migrate-at-start=true

# Security
quarkus.oidc.enabled=true
quarkus.oidc.auth-server-url=${OIDC_SERVER_URL:https://idp.example.com/realms/pki}
quarkus.oidc.client-id=ca-service
quarkus.oidc.credentials.secret=${OIDC_CLIENT_SECRET}

# Kafka
kafka.bootstrap.servers=${KAFKA_BROKERS:localhost:9092}
mp.messaging.outgoing.certificate-events.connector=smallrye-kafka
mp.messaging.outgoing.certificate-events.topic=pki.certificate.events
mp.messaging.outgoing.certificate-events.value.serializer=io.quarkus.kafka.client.serialization.ObjectMapperSerializer

# Metrics
quarkus.micrometer.enabled=true
quarkus.micrometer.export.prometheus.enabled=true
quarkus.micrometer.binder.http-server.enabled=true

# Tracing
quarkus.otel.enabled=true
quarkus.otel.exporter.otlp.endpoint=${OTEL_ENDPOINT:http://localhost:4317}
quarkus.otel.traces.sampler=always_on

# Health
quarkus.health.enabled=true

# OpenAPI
quarkus.smallrye-openapi.path=/openapi
quarkus.swagger-ui.always-include=true
quarkus.swagger-ui.path=/swagger-ui

# Logging
quarkus.log.level=INFO
quarkus.log.category."org.dogtagpki".level=DEBUG
quarkus.log.console.json=true
```

#### 1.3.3 Domain Model

```java
package org.dogtagpki.ca.model;

import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import jakarta.persistence.*;
import java.math.BigInteger;
import java.time.Instant;

@Entity
@Table(name = "certificates", indexes = {
    @Index(name = "idx_cert_serial", columnList = "serialNumber"),
    @Index(name = "idx_cert_subject", columnList = "subjectDN"),
    @Index(name = "idx_cert_status", columnList = "status")
})
public class Certificate extends PanacheEntityBase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    @Column(nullable = false, unique = true, length = 64)
    public String serialNumber;

    @Column(nullable = false, columnDefinition = "TEXT")
    public String subjectDN;

    @Column(nullable = false, columnDefinition = "TEXT")
    public String issuerDN;

    @Column(nullable = false)
    public Instant notBefore;

    @Column(nullable = false)
    public Instant notAfter;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    public CertificateStatus status;

    @Column(nullable = false, columnDefinition = "BYTEA")
    public byte[] derEncoding;

    @Column(columnDefinition = "JSONB")
    public String metadata;

    @Column(nullable = false)
    public Instant createdAt;

    @Column(nullable = false)
    public Instant updatedAt;

    @Version
    public Long version;

    @PrePersist
    public void prePersist() {
        createdAt = Instant.now();
        updatedAt = Instant.now();
    }

    @PreUpdate
    public void preUpdate() {
        updatedAt = Instant.now();
    }

    public enum CertificateStatus {
        VALID,
        REVOKED,
        EXPIRED,
        ON_HOLD
    }
}
```

```java
package org.dogtagpki.ca.model;

import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "cert_requests")
public class CertRequest extends PanacheEntityBase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    @Column(nullable = false, unique = true)
    public String requestId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    public RequestType type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    public RequestStatus status;

    @Column(nullable = false)
    public String profileId;

    @Column(columnDefinition = "TEXT")
    public String subjectDN;

    @Column(columnDefinition = "TEXT")
    public String csr;

    @Column
    public String serialNumber; // Issued certificate serial

    @Column(nullable = false)
    public String requestorId;

    @Column(columnDefinition = "JSONB")
    public String requestData;

    @Column(columnDefinition = "TEXT")
    public String notes;

    @Column(nullable = false)
    public Instant createdAt;

    @Column(nullable = false)
    public Instant updatedAt;

    public enum RequestType {
        ENROLLMENT,
        RENEWAL,
        REVOCATION
    }

    public enum RequestStatus {
        PENDING,
        APPROVED,
        REJECTED,
        COMPLETE,
        CANCELLED
    }
}
```

#### 1.3.4 Repository Layer

```java
package org.dogtagpki.ca.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepository;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import org.dogtagpki.ca.model.Certificate;
import org.dogtagpki.ca.model.Certificate.CertificateStatus;

import java.util.List;

@ApplicationScoped
public class CertificateRepository implements PanacheRepository<Certificate> {

    public Uni<Certificate> findBySerialNumber(String serialNumber) {
        return find("serialNumber", serialNumber).firstResult();
    }

    public Uni<List<Certificate>> findBySubjectDN(String subjectDN) {
        return find("subjectDN", subjectDN).list();
    }

    public Uni<List<Certificate>> findByStatus(CertificateStatus status) {
        return find("status", status).list();
    }

    public Uni<List<Certificate>> findExpiring(int daysFromNow) {
        return find(
            "notAfter BETWEEN CURRENT_TIMESTAMP AND CURRENT_TIMESTAMP + INTERVAL '?1 days'",
            daysFromNow
        ).list();
    }

    public Uni<Long> countByStatus(CertificateStatus status) {
        return count("status", status);
    }
}
```

#### 1.3.5 Service Layer

```java
package org.dogtagpki.ca.service;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.dogtagpki.ca.crypto.SigningEngine;
import org.dogtagpki.ca.event.CertificateEvent;
import org.dogtagpki.ca.event.EventPublisher;
import org.dogtagpki.ca.model.Certificate;
import org.dogtagpki.ca.model.CertRequest;
import org.dogtagpki.ca.repository.CertificateRepository;
import org.dogtagpki.ca.repository.CertRequestRepository;
import org.eclipse.microprofile.metrics.MetricUnits;
import org.eclipse.microprofile.metrics.annotation.Counted;
import org.eclipse.microprofile.metrics.annotation.Timed;
import org.jboss.logging.Logger;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;

@ApplicationScoped
public class EnrollmentService {

    private static final Logger LOG = Logger.getLogger(EnrollmentService.class);

    @Inject
    CertificateRepository certRepo;

    @Inject
    CertRequestRepository requestRepo;

    @Inject
    ProfileEngine profileEngine;

    @Inject
    SigningEngine signingEngine;

    @Inject
    EventPublisher eventPublisher;

    @Inject
    AuditService auditService;

    @Transactional
    @Counted(name = "enrollmentRequests", description = "Number of enrollment requests")
    @Timed(name = "enrollmentDuration", description = "Enrollment processing time", unit = MetricUnits.MILLISECONDS)
    public Uni<EnrollmentResult> enroll(EnrollmentRequest request) {
        LOG.infof("Processing enrollment request for subject: %s", request.subjectDN);

        return createCertRequest(request)
            .flatMap(certRequest -> validateRequest(certRequest)
                .flatMap(validated -> profileEngine.applyProfile(validated, request.profileId))
                .flatMap(this::generateCertificate)
                .flatMap(cert -> persistCertificate(cert, certRequest))
                .invoke(cert -> publishEvent(cert, "ISSUED"))
                .invoke(cert -> auditService.logIssuance(cert))
                .map(cert -> new EnrollmentResult(cert, certRequest))
            )
            .onFailure().invoke(error -> LOG.errorf(error, "Enrollment failed"));
    }

    private Uni<CertRequest> createCertRequest(EnrollmentRequest request) {
        CertRequest certRequest = new CertRequest();
        certRequest.requestId = generateRequestId();
        certRequest.type = CertRequest.RequestType.ENROLLMENT;
        certRequest.status = CertRequest.RequestStatus.PENDING;
        certRequest.profileId = request.profileId;
        certRequest.subjectDN = request.subjectDN;
        certRequest.csr = request.csr;
        certRequest.requestorId = request.requestorId;
        certRequest.createdAt = Instant.now();
        certRequest.updatedAt = Instant.now();

        return requestRepo.persist(certRequest);
    }

    private Uni<CertRequest> validateRequest(CertRequest request) {
        // Validation logic
        return Uni.createFrom().item(request);
    }

    private Uni<X509Certificate> generateCertificate(CertRequest request) {
        return signingEngine.signCertificate(request);
    }

    private Uni<Certificate> persistCertificate(X509Certificate x509Cert, CertRequest request) {
        Certificate cert = new Certificate();
        cert.serialNumber = x509Cert.getSerialNumber().toString(16);
        cert.subjectDN = x509Cert.getSubjectDN().getName();
        cert.issuerDN = x509Cert.getIssuerDN().getName();
        cert.notBefore = x509Cert.getNotBefore().toInstant();
        cert.notAfter = x509Cert.getNotAfter().toInstant();
        cert.status = Certificate.CertificateStatus.VALID;

        try {
            cert.derEncoding = x509Cert.getEncoded();
        } catch (Exception e) {
            return Uni.createFrom().failure(e);
        }

        return certRepo.persist(cert)
            .flatMap(savedCert -> {
                request.status = CertRequest.RequestStatus.COMPLETE;
                request.serialNumber = cert.serialNumber;
                request.updatedAt = Instant.now();
                return requestRepo.persist(request)
                    .replaceWith(savedCert);
            });
    }

    private void publishEvent(Certificate cert, String eventType) {
        CertificateEvent event = new CertificateEvent(
            eventType,
            cert.serialNumber,
            cert.subjectDN,
            Instant.now()
        );
        eventPublisher.publish(event);
    }

    private String generateRequestId() {
        return "REQ-" + System.currentTimeMillis() + "-" +
               new BigInteger(64, new java.security.SecureRandom()).toString(36).toUpperCase();
    }

    public record EnrollmentRequest(
        String profileId,
        String subjectDN,
        String csr,
        String requestorId
    ) {}

    public record EnrollmentResult(
        Certificate certificate,
        CertRequest request
    ) {}
}
```

#### 1.3.6 REST API Layer

```java
package org.dogtagpki.ca.rest;

import io.quarkus.security.Authenticated;
import io.smallrye.mutiny.Uni;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dogtagpki.ca.service.EnrollmentService;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

@Path("/api/v2/certrequests")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Certificate Requests", description = "Certificate enrollment and management")
public class CertRequestResource {

    @Inject
    EnrollmentService enrollmentService;

    @POST
    @RolesAllowed({"ca-agent", "ca-admin"})
    @Operation(summary = "Submit certificate enrollment request")
    @APIResponse(responseCode = "201", description = "Certificate issued successfully")
    @APIResponse(responseCode = "400", description = "Invalid request")
    @APIResponse(responseCode = "403", description = "Forbidden")
    public Uni<Response> enroll(@Valid EnrollmentRequest request) {
        return enrollmentService.enroll(
            new EnrollmentService.EnrollmentRequest(
                request.profileId,
                request.subjectDN,
                request.csr,
                request.requestorId
            )
        )
        .onItem().transform(result ->
            Response.status(Response.Status.CREATED)
                .entity(result)
                .build()
        )
        .onFailure().recoverWithItem(error ->
            Response.status(Response.Status.BAD_REQUEST)
                .entity(new ErrorResponse(error.getMessage()))
                .build()
        );
    }

    @GET
    @Path("/{requestId}")
    @Authenticated
    @Operation(summary = "Get certificate request by ID")
    public Uni<Response> getRequest(@PathParam("requestId") String requestId) {
        return enrollmentService.getRequest(requestId)
            .onItem().ifNotNull().transform(req -> Response.ok(req).build())
            .onItem().ifNull().continueWith(Response.status(Response.Status.NOT_FOUND).build());
    }

    public record EnrollmentRequest(
        String profileId,
        String subjectDN,
        String csr,
        String requestorId
    ) {}

    public record ErrorResponse(String message) {}
}
```


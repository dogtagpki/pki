# PKI Certificate Notification System Plan

This document outlines the comprehensive notification system for Dogtag PKI certificate lifecycle events, supporting multiple delivery mechanisms including Webhooks, Kafka, and RabbitMQ.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Notification Channels](#notification-channels)
4. [Event Types](#event-types)
5. [Message Format](#message-format)
6. [Device Metadata](#device-metadata)
7. [Routing & Filtering](#routing--filtering)
8. [Configuration](#configuration)
9. [Use Cases](#use-cases)
10. [Security](#security)
11. [Storage Backend](#storage-backend)
12. [Monitoring & Operations](#monitoring--operations)

---

## Overview

### Goals

- **Real-time visibility** into certificate lifecycle events
- **Integration flexibility** with enterprise systems (SIEM, CMDB, alerting)
- **Device-aware routing** to send notifications based on certificate metadata
- **Reliable delivery** with guaranteed message delivery options
- **Scalability** to handle high-volume certificate operations

### Supported Notification Channels

| Channel | Delivery Model | Best For |
|---------|---------------|----------|
| **Webhook** | Push (HTTP POST) | Simple integrations, Slack, Teams, custom APIs |
| **Kafka** | Pub/Sub (streaming) | Enterprise integration, high volume, multiple consumers |
| **RabbitMQ** | Message Queue | Reliable delivery, complex routing, legacy systems |

### Key Features

- Unified event format across all channels
- Device-type filtering (server, IoT, mobile, container, etc.)
- Event-type filtering (issued, revoked, renewed, expired)
- Configurable per-channel routing rules
- Retry and dead-letter handling
- HMAC signing for webhooks, TLS for message queues

---

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DOGTAG PKI CA                                   │
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────────────────────────┐ │
│  │  Enrollment  │    │   Request    │    │       RequestNotifier          │ │
│  │   Profile    │───▶│    Queue     │───▶│         (listeners)            │ │
│  │              │    │              │    │                                │ │
│  │ DeviceInfo   │    │ State Engine │    │  ┌──────────────────────────┐  │ │
│  │ (metadata)   │    │              │    │  │  NotificationListener    │  │ │
│  └──────────────┘    └──────────────┘    │  │                          │  │ │
│                                          │  │  • Event Detection       │  │ │
│                                          │  │  • Payload Building      │  │ │
│                                          │  │  • Routing Decisions     │  │ │
│                                          │  └────────────┬─────────────┘  │ │
│                                          └───────────────┼────────────────┘ │
│                                                          │                   │
│  ┌───────────────────────────────────────────────────────┼─────────────────┐│
│  │                    NOTIFICATION DISPATCHER            │                  ││
│  │                                                       ▼                  ││
│  │  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐            ││
│  │  │   Webhook   │   │    Kafka    │   │     RabbitMQ        │            ││
│  │  │  Dispatcher │   │  Producer   │   │     Publisher       │            ││
│  │  │             │   │             │   │                     │            ││
│  │  │ • HTTP POST │   │ • Topics    │   │ • Exchanges         │            ││
│  │  │ • Retry     │   │ • Partitions│   │ • Queues            │            ││
│  │  │ • HMAC Sign │   │ • Acks      │   │ • Routing Keys      │            ││
│  │  └──────┬──────┘   └──────┬──────┘   └──────────┬──────────┘            ││
│  └─────────┼─────────────────┼──────────────────────┼──────────────────────┘│
└────────────┼─────────────────┼──────────────────────┼───────────────────────┘
             │                 │                      │
             ▼                 ▼                      ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────────┐
│    WEBHOOKS     │  │     KAFKA       │  │          RABBITMQ               │
│                 │  │     CLUSTER     │  │           CLUSTER               │
│ • Slack         │  │                 │  │                                 │
│ • Teams         │  │ ┌─────────────┐ │  │  ┌───────────┐  ┌────────────┐  │
│ • PagerDuty     │  │ │ Topic:      │ │  │  │ Exchange: │  │ Queues:    │  │
│ • Custom APIs   │  │ │ pki.events  │ │  │  │ pki.events│  │            │  │
│ • ServiceNow    │  │ └─────────────┘ │  │  └───────────┘  │ • siem     │  │
└─────────────────┘  │        │        │  │        │        │ • cmdb     │  │
                     │        ▼        │  │        │        │ • alerts   │  │
                     │ ┌─────────────┐ │  │        ▼        └────────────┘  │
                     │ │ Consumers:  │ │  │  ┌───────────┐                  │
                     │ │ • SIEM      │ │  │  │ Consumers │                  │
                     │ │ • Analytics │ │  │  └───────────┘                  │
                     │ │ • Archival  │ │  │                                 │
                     │ └─────────────┘ │  │                                 │
                     └─────────────────┘  └─────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| **NotificationListener** | Receives certificate events, builds payloads, determines routing |
| **WebhookDispatcher** | HTTP delivery with retry, signing, timeout handling |
| **KafkaProducer** | Publishes to Kafka topics with partitioning by device type |
| **RabbitMQPublisher** | Publishes to exchanges with routing key support |
| **ConfigManager** | Loads and manages notification channel configuration |

---

## Notification Channels

### Webhook

**Delivery Model**: Synchronous HTTP POST with async retry

**Characteristics**:
- Push-based delivery to HTTP endpoints
- HMAC-SHA256 payload signing
- Configurable retry with exponential backoff
- Per-endpoint event and device type filtering

**Best For**:
- Slack, Microsoft Teams integration
- Simple custom API integrations
- Low-volume, targeted notifications
- Systems without message queue infrastructure

**Limitations**:
- Requires endpoint availability
- No built-in buffering (retry only)
- Single consumer per endpoint

---

### Apache Kafka

**Delivery Model**: Publish/Subscribe streaming

**Characteristics**:
- High-throughput, distributed streaming
- Persistent message log with configurable retention
- Multiple consumer groups for parallel processing
- Partitioning by device type or other keys
- Exactly-once semantics available

**Topic Structure**:
```
pki.events                    # All events (default)
pki.events.issued             # Issued certificates only
pki.events.revoked            # Revoked certificates only
pki.events.device.iot         # IoT device events only
pki.events.device.server      # Server events only
```

**Best For**:
- High-volume certificate operations
- Multiple consumers needing same events
- Event sourcing and audit trails
- Real-time analytics and dashboards
- Microservices architectures

**Consumer Examples**:
- SIEM (Splunk, Elastic, QRadar)
- CMDB updates
- Analytics pipelines
- Compliance archival
- Real-time dashboards

---

### RabbitMQ

**Delivery Model**: Message Queue with flexible routing

**Characteristics**:
- Reliable message delivery with acknowledgments
- Flexible routing via exchanges and binding keys
- Dead-letter queues for failed messages
- Message TTL and priority support
- Multiple exchange types (direct, topic, fanout, headers)

**Exchange/Queue Structure**:
```
Exchange: pki.events (topic type)
  │
  ├── Routing Key: certificate.issued.*
  │   └── Queue: pki-issued-queue → CMDB Consumer
  │
  ├── Routing Key: certificate.revoked.*
  │   └── Queue: pki-revoked-queue → Security Alerting
  │
  ├── Routing Key: certificate.*.iot
  │   └── Queue: pki-iot-queue → IoT Platform
  │
  └── Routing Key: certificate.#
      └── Queue: pki-all-queue → SIEM / Archival
```

**Best For**:
- Complex routing requirements
- Guaranteed delivery requirements
- Integration with legacy systems
- Request/reply patterns
- Work queue distribution

---

## Event Types

### Certificate Lifecycle Events

| Event | Trigger | Severity |
|-------|---------|----------|
| `certificate.issued` | New certificate issued | Info |
| `certificate.renewed` | Certificate renewed | Info |
| `certificate.revoked` | Certificate revoked | Warning |
| `certificate.expired` | Certificate expired | Warning |
| `certificate.expiring` | Certificate expiring soon | Warning |
| `request.pending` | Request awaiting approval | Info |
| `request.approved` | Request approved by agent | Info |
| `request.rejected` | Request rejected | Warning |

### Event Metadata

Each event includes:
- Event type and timestamp
- Certificate details (serial, subject, issuer, validity)
- Device metadata (type, ID, group, environment)
- Request information (ID, type, requestor)
- PKI instance identifier

---

## Message Format

### Unified Event Schema

All notification channels use the same JSON event format:

```json
{
  "specversion": "1.0",
  "type": "com.redhat.pki.certificate.issued",
  "source": "/pki/ca/pki-tomcat",
  "id": "evt-20240115-001234",
  "time": "2024-01-15T10:30:00.000Z",
  "datacontenttype": "application/json",
  "data": {
    "certificate": {
      "serialNumber": "12345",
      "serialNumberHex": "0x3039",
      "subjectDN": "CN=device001.example.com,O=Example Corp",
      "issuerDN": "CN=Example CA,O=Example Corp",
      "notBefore": "2024-01-15T00:00:00Z",
      "notAfter": "2025-01-15T00:00:00Z",
      "profileId": "caServerCert",
      "fingerprint": "SHA256:AB:CD:EF:..."
    },
    "device": {
      "type": "iot",
      "id": "sensor-001",
      "group": "factory-floor",
      "environment": "production",
      "location": "building-a",
      "owner": "iot-team"
    },
    "request": {
      "id": "req-98765",
      "type": "enrollment",
      "status": "complete",
      "requestorName": "John Smith",
      "requestorEmail": "jsmith@example.com",
      "submittedAt": "2024-01-15T10:25:00Z"
    }
  }
}
```

### Channel-Specific Adaptations

| Channel | Adaptation |
|---------|------------|
| **Webhook** | JSON body + HTTP headers (X-PKI-Event, X-PKI-Signature) |
| **Kafka** | JSON value + message key (deviceType) + headers |
| **RabbitMQ** | JSON body + routing key (event.deviceType) + properties |

---

## Device Metadata

### Supported Device Types

| Type | Description | Examples |
|------|-------------|----------|
| `server` | Traditional servers | Web servers, databases, app servers |
| `iot` | IoT devices | Sensors, actuators, edge devices |
| `mobile` | Mobile devices | Smartphones, tablets |
| `workstation` | End-user devices | Laptops, desktops |
| `network` | Network equipment | Routers, switches, firewalls |
| `container` | Containerized workloads | Docker, Kubernetes pods |
| `service` | Service identities | APIs, microservices, automation |

### Metadata Fields

| Field | Description | Example |
|-------|-------------|---------|
| `deviceType` | Category of device | `iot` |
| `deviceId` | Unique identifier | `sensor-001` |
| `deviceGroup` | Logical grouping | `factory-floor` |
| `deviceEnvironment` | Deployment environment | `production` |
| `deviceLocation` | Physical/logical location | `building-a` |
| `deviceOwner` | Responsible team/person | `iot-team` |

### Metadata Capture

Device metadata is captured during certificate enrollment via a profile input plugin and stored with the certificate request for inclusion in notifications.

---

## Routing & Filtering

### Filter Dimensions

Notifications can be filtered by:

1. **Event Type**: issued, revoked, renewed, expired, pending, rejected
2. **Device Type**: server, iot, mobile, workstation, network, container, service
3. **Device Group**: Custom groupings (e.g., "production-web", "factory-sensors")
4. **Environment**: production, staging, development, test

### Routing Examples

| Rule | Webhook | Kafka Topic | RabbitMQ Routing Key |
|------|---------|-------------|---------------------|
| All events | `*` events | `pki.events` | `certificate.#` |
| Revocations only | `revoked` | `pki.events.revoked` | `certificate.revoked.*` |
| IoT devices | `deviceTypes=iot` | `pki.events.device.iot` | `certificate.*.iot` |
| Production servers | `deviceTypes=server` + filter | `pki.events.device.server` | `certificate.*.server.production` |
| Security events | `revoked,rejected` | `pki.events.security` | `certificate.revoked.#` |

### Multi-Channel Routing

A single event can be routed to multiple channels simultaneously:

```
Certificate Revoked (IoT device)
    │
    ├──▶ Webhook: Slack #security-alerts
    ├──▶ Webhook: PagerDuty (critical)
    ├──▶ Kafka: pki.events.revoked
    ├──▶ Kafka: pki.events.device.iot
    └──▶ RabbitMQ: security-queue (for SIEM)
```

---

## Configuration

### Global Settings

```properties
# Enable notification system
ca.notification.enable=true

# Channels to enable
ca.notification.channels=webhook,kafka,rabbitmq

# Global retry settings
ca.notification.retry.maxAttempts=3
ca.notification.retry.initialDelayMs=1000
ca.notification.retry.maxDelayMs=30000
ca.notification.retry.multiplier=2.0
```

### Webhook Configuration

```properties
# Webhook channel settings
ca.notification.webhook.enable=true
ca.notification.webhook.threadPoolSize=5

# Webhook instance: Slack
ca.notification.webhook.instance.slack.url=https://hooks.slack.com/services/XXX
ca.notification.webhook.instance.slack.events=issued,revoked,rejected
ca.notification.webhook.instance.slack.deviceTypes=*
ca.notification.webhook.instance.slack.secret=slack-signing-secret
ca.notification.webhook.instance.slack.timeout=30
ca.notification.webhook.instance.slack.enabled=true
```

### Kafka Configuration

```properties
# Kafka channel settings
ca.notification.kafka.enable=true
ca.notification.kafka.bootstrap.servers=kafka1:9092,kafka2:9092,kafka3:9092

# Topic configuration
ca.notification.kafka.topic.default=pki.events
ca.notification.kafka.topic.byEventType=true
ca.notification.kafka.topic.byDeviceType=true

# Producer settings
ca.notification.kafka.producer.acks=all
ca.notification.kafka.producer.retries=3
ca.notification.kafka.producer.batchSize=16384
ca.notification.kafka.producer.lingerMs=5
ca.notification.kafka.producer.compressionType=snappy

# Security (SASL/SSL)
ca.notification.kafka.security.protocol=SASL_SSL
ca.notification.kafka.sasl.mechanism=SCRAM-SHA-512
ca.notification.kafka.sasl.username=pki-producer
ca.notification.kafka.sasl.password=<password>
ca.notification.kafka.ssl.truststoreLocation=/path/to/truststore.jks
ca.notification.kafka.ssl.truststorePassword=<password>

# Topic routing rules
ca.notification.kafka.route.revoked.topic=pki.events.security
ca.notification.kafka.route.iot.topic=pki.events.iot
```

### RabbitMQ Configuration

```properties
# RabbitMQ channel settings
ca.notification.rabbitmq.enable=true
ca.notification.rabbitmq.host=rabbitmq.example.com
ca.notification.rabbitmq.port=5671
ca.notification.rabbitmq.virtualHost=/pki
ca.notification.rabbitmq.username=pki-publisher
ca.notification.rabbitmq.password=<password>

# Exchange configuration
ca.notification.rabbitmq.exchange.name=pki.events
ca.notification.rabbitmq.exchange.type=topic
ca.notification.rabbitmq.exchange.durable=true

# Message settings
ca.notification.rabbitmq.message.persistent=true
ca.notification.rabbitmq.message.contentType=application/json

# Routing key pattern: certificate.<event>.<deviceType>
ca.notification.rabbitmq.routingKey.pattern=certificate.{event}.{deviceType}

# TLS settings
ca.notification.rabbitmq.ssl.enabled=true
ca.notification.rabbitmq.ssl.truststoreLocation=/path/to/truststore.jks
ca.notification.rabbitmq.ssl.truststorePassword=<password>

# Connection pool
ca.notification.rabbitmq.connection.poolSize=5
ca.notification.rabbitmq.connection.timeout=30000
```

---

## Use Cases

### 1. Security Operations (SIEM Integration)

**Channels**: Kafka + Syslog

**Flow**:
```
Revocation Event → Kafka (pki.events.security) → SIEM Consumer → Splunk/QRadar
```

**Events**: revoked, rejected, expired

**Purpose**: Real-time security alerting, compliance monitoring, forensics

---

### 2. IT Operations (ServiceNow/CMDB)

**Channels**: Webhook or RabbitMQ

**Flow**:
```
Issued/Revoked → RabbitMQ → ServiceNow Integration → CMDB Update
```

**Events**: issued, renewed, revoked, expired

**Purpose**: Keep CMDB current with certificate inventory

---

### 3. DevOps Alerting (Slack/PagerDuty)

**Channels**: Webhook

**Flow**:
```
Expiring Soon → Webhook → Slack Channel
Revocation → Webhook → PagerDuty → On-call Engineer
```

**Events**: expiring, revoked, rejected

**Purpose**: Proactive alerting for certificate issues

---

### 4. IoT Platform Integration

**Channels**: Kafka or RabbitMQ

**Flow**:
```
IoT Cert Issued → Kafka (pki.events.device.iot) → IoT Platform → Device Registry
```

**Events**: issued, revoked, expired
**Device Filter**: iot, network

**Purpose**: Sync certificate status with IoT device management platform

---

### 5. Compliance & Audit

**Channels**: Kafka (long retention)

**Flow**:
```
All Events → Kafka (pki.events.audit) → S3/HDFS Archival
```

**Events**: All
**Retention**: 7 years

**Purpose**: Regulatory compliance, audit trails

---

### 6. Real-time Dashboard

**Channels**: Kafka → WebSocket

**Flow**:
```
All Events → Kafka → Dashboard Backend → WebSocket → Browser
```

**Purpose**: Live certificate activity monitoring

---

## Security

### Authentication & Authorization

| Channel | Authentication | Authorization |
|---------|---------------|---------------|
| Webhook | HMAC-SHA256 signature | Endpoint validates signature |
| Kafka | SASL (SCRAM/GSSAPI) + TLS | Topic ACLs |
| RabbitMQ | Username/Password + TLS | Vhost/Exchange permissions |

### Data Protection

- **In Transit**: TLS 1.2+ for all channels
- **At Rest**: Encrypted message queues (Kafka/RabbitMQ encryption)
- **Secrets**: Credentials stored in secure configuration or vault

### Sensitive Data Handling

The following fields are **excluded** from notifications:
- Private keys
- Challenge passwords
- Authentication tokens
- Full certificate PEM (only fingerprint included)

---

## Storage Backend

The notification system uses PostgreSQL for persistent storage and Redis for caching and temporary data.

### PostgreSQL (Persistent Storage)

| Table | Purpose |
|-------|---------|
| `webhook_configs` | Webhook endpoint configurations |
| `webhook_deliveries` | Delivery attempt history and status |
| `notification_events` | Event log for audit trail |
| `dead_letter_queue` | Failed messages for retry/analysis |

```sql
-- Webhook configurations
CREATE TABLE webhook_configs (
    id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    url TEXT NOT NULL,
    events TEXT[] NOT NULL,
    device_types TEXT[] DEFAULT '{"*"}',
    secret_encrypted BYTEA,
    timeout_seconds INT DEFAULT 30,
    retries INT DEFAULT 3,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Delivery tracking
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY,
    webhook_id UUID REFERENCES webhook_configs(id),
    event_type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL, -- pending, success, failed
    attempts INT DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    response_code INT,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for finding pending deliveries
CREATE INDEX idx_deliveries_pending ON webhook_deliveries(status, created_at)
    WHERE status = 'pending';
```

### Redis (Cache & Queues)

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `notify:queue:{channel}` | Pending notification queue (List) | None |
| `notify:processing:{delivery_id}` | In-flight delivery lock | 5 min |
| `notify:ratelimit:{webhook_id}` | Per-webhook rate limiting | 1 min |
| `notify:circuit:{webhook_id}` | Circuit breaker state | 5 min |
| `notify:stats:{webhook_id}:{date}` | Daily delivery statistics | 7 days |

### Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Event     │────▶│   Redis     │────▶│  Dispatcher │────▶│  Endpoint   │
│  Generated  │     │   Queue     │     │   Workers   │     │             │
└─────────────┘     └─────────────┘     └──────┬──────┘     └─────────────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │ PostgreSQL  │
                                        │ (delivery   │
                                        │   history)  │
                                        └─────────────┘
```

---

## Monitoring & Operations

### Health Checks

| Check | Description |
|-------|-------------|
| Webhook endpoint reachability | HTTP HEAD to configured URLs |
| Kafka broker connectivity | Metadata request to bootstrap servers |
| RabbitMQ connection status | AMQP connection health |
| Queue depth monitoring | Alert on growing backlogs |

### Metrics

| Metric | Description |
|--------|-------------|
| `pki.notification.sent.total` | Total notifications sent (by channel, event type) |
| `pki.notification.failed.total` | Failed deliveries |
| `pki.notification.retry.total` | Retry attempts |
| `pki.notification.latency.ms` | Delivery latency |
| `pki.notification.queue.depth` | Pending notifications |

### Dead Letter Handling

Failed messages after all retries are:
- **Webhook**: Logged with full payload for manual retry
- **Kafka**: Sent to `pki.events.dlq` topic
- **RabbitMQ**: Routed to `pki.events.dlq` queue

### Alerting Thresholds

| Condition | Threshold | Action |
|-----------|-----------|--------|
| Delivery failure rate | > 5% over 5 min | Warning alert |
| Dead letter queue depth | > 100 messages | Critical alert |
| Kafka consumer lag | > 10,000 messages | Warning alert |
| Webhook latency | > 5 seconds P95 | Warning alert |

---

## Implementation Phases

### Phase 1: Webhook (Complete)
- [x] WebhookListener implementation
- [x] WebhookDispatcher with retry
- [x] HMAC signing
- [x] Device-type filtering
- [x] Configuration support

### Phase 2: Kafka
- [ ] KafkaProducer integration
- [ ] Topic management
- [ ] Partitioning by device type
- [ ] SASL/SSL security
- [ ] Dead letter topic

### Phase 3: RabbitMQ
- [ ] RabbitMQ publisher
- [ ] Exchange/queue setup
- [ ] Routing key patterns
- [ ] TLS security
- [ ] Dead letter queue

### Phase 4: Operations
- [ ] Metrics and monitoring
- [ ] Health check endpoints
- [ ] Admin UI for configuration
- [ ] Documentation and runbooks

---

## Summary

The PKI notification system provides flexible, reliable delivery of certificate lifecycle events through multiple channels:

| Channel | Strength | Use When |
|---------|----------|----------|
| **Webhook** | Simple, universal | Quick integrations, Slack/Teams |
| **Kafka** | Scalable, durable | High volume, multiple consumers, analytics |
| **RabbitMQ** | Reliable, flexible routing | Complex routing, guaranteed delivery |

All channels share:
- Unified event format
- Device-type awareness
- Configurable filtering
- Security (signing/TLS)
- Retry handling

This multi-channel approach ensures PKI events can reach any system in the enterprise, from chat applications to SIEM platforms to IoT management systems.

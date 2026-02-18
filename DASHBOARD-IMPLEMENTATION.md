# PKI Dashboard Implementation Guide

This document describes the implementation of a modern, user-centric PKI dashboard with webhook notifications and device-based certificate lifecycle management.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Webhook Listener](#webhook-listener)
4. [Dashboard REST API](#dashboard-rest-api)
5. [Access Control](#access-control)
6. [Frontend UI](#frontend-ui)
7. [Device Metadata](#device-metadata)
8. [Configuration](#configuration)
9. [Files Created](#files-created)
10. [Storage Backend](#storage-backend)
11. [Future Enhancements](#future-enhancements)
12. [Testing](#testing)
13. [References](#references)

---

## Overview

This implementation adds three major features to Dogtag PKI:

1. **Webhook Notifications**: Event-driven notifications for certificate lifecycle events (issued, revoked, renewed, expired)
2. **User Dashboard**: Self-service portal where users can view and manage their own certificates
3. **Device Metadata**: Track device type, group, and environment for certificates to enable targeted notifications

### Key Benefits

- Users can self-manage certificates without agent intervention
- Automated notifications to external systems (Slack, Teams, custom webhooks)
- Device-based filtering for IoT, server, mobile, and container certificates
- Expiration warnings and renewal workflows

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Dogtag PKI CA                                   │
│                                                                              │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐           │
│  │   Profile   │───▶│  Request Queue   │───▶│ RequestNotifier   │           │
│  │ (metadata)  │    │  (state engine)  │    │   (listeners)     │           │
│  └─────────────┘    └──────────────────┘    └─────────┬─────────┘           │
│        │                                              │                      │
│        │ DeviceInfoInput                              │                      │
│        │ (deviceType, deviceId, deviceGroup)          │                      │
│        ▼                                              ▼                      │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         WebhookListener                                  ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐          ││
│  │  │ DeviceType  │  │  Webhook    │  │  Notification Router    │          ││
│  │  │  Resolver   │  │ Dispatcher  │  │  (filter by metadata)   │          ││
│  │  └─────────────┘  └──────┬──────┘  └─────────────────────────┘          ││
│  └──────────────────────────┼──────────────────────────────────────────────┘│
│                             │                                                │
└─────────────────────────────┼────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
   ┌──────────┐        ┌──────────┐         ┌──────────┐
   │ Webhook  │        │ Webhook  │         │ Webhook  │
   │ Endpoint │        │ Endpoint │         │ Endpoint │
   │ (Slack)  │        │ (Teams)  │         │ (Custom) │
   └──────────┘        └──────────┘         └──────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                          User Dashboard                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐          │
│  │  Certificate    │  │   Device Type   │  │  Expiration         │          │
│  │   Overview      │  │   Statistics    │  │  Timeline           │          │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘          │
│                              │                                               │
│                    REST API (/v2/dashboard/*)                               │
│                              │                                               │
│  ┌───────────────────────────┴───────────────────────────────────┐          │
│  │                    Access Control                              │          │
│  │  • Authentication (cert/password/SSO)                         │          │
│  │  • User-based filtering (see only own certs)                  │          │
│  │  • ACL: certServer.ee.dashboard,read                          │          │
│  └───────────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Webhook Listener

### Components

| Class | Purpose |
|-------|---------|
| `WebhookListener` | Main listener that triggers on certificate events |
| `WebhookConfig` | Configuration for individual webhook endpoints |
| `WebhookPayload` | JSON payload structure sent to webhooks |
| `WebhookDispatcher` | Async HTTP dispatcher with retry and HMAC signing |

### Supported Events

| Event | Trigger |
|-------|---------|
| `certificate.issued` | New certificate issued |
| `certificate.renewed` | Certificate renewed |
| `certificate.revoked` | Certificate revoked |
| `certificate.rejected` | Request rejected |
| `certificate.pending` | Request awaiting approval |

### Webhook Payload Structure

```json
{
  "event": "certificate.issued",
  "timestamp": "2024-01-15T10:30:00Z",
  "instanceId": "pki-tomcat",
  "certificate": {
    "serialNumber": "12345",
    "serialNumberHex": "0x3039",
    "subjectDN": "CN=device001.example.com",
    "issuerDN": "CN=CA Signing Certificate",
    "notBefore": "Jan 15, 2024 10:30:00 AM",
    "notAfter": "Jan 15, 2025 10:30:00 AM",
    "profileId": "caServerCert"
  },
  "device": {
    "type": "iot",
    "id": "sensor-001",
    "group": "factory-sensors"
  },
  "request": {
    "id": "123",
    "type": "enrollment",
    "status": "complete",
    "requestorName": "admin",
    "requestorEmail": "admin@example.com"
  }
}
```

### Security Features

- **HMAC-SHA256 Signing**: Payloads signed with `X-PKI-Signature-256` header
- **Retry with Exponential Backoff**: 1s, 2s, 4s, 8s between retries
- **Configurable Timeouts**: Per-webhook connection timeouts
- **Async Delivery**: Thread pool prevents blocking certificate operations

### Configuration Example

Add to `CS.cfg`:

```properties
# Enable webhook notifications
ca.notification.webhook.enable=true
ca.notification.webhook.threadPoolSize=5

# Slack webhook for all certificate events
ca.notification.webhook.instance.slack.url=https://hooks.slack.com/services/XXX/YYY/ZZZ
ca.notification.webhook.instance.slack.events=issued,revoked,rejected,renewed
ca.notification.webhook.instance.slack.deviceTypes=*
ca.notification.webhook.instance.slack.secret=my-hmac-secret
ca.notification.webhook.instance.slack.timeout=30
ca.notification.webhook.instance.slack.retries=3
ca.notification.webhook.instance.slack.enabled=true

# Teams webhook for IoT device revocations only
ca.notification.webhook.instance.iot-alerts.url=https://outlook.office.com/webhook/XXX
ca.notification.webhook.instance.iot-alerts.events=revoked
ca.notification.webhook.instance.iot-alerts.deviceTypes=iot,network
ca.notification.webhook.instance.iot-alerts.timeout=15
ca.notification.webhook.instance.iot-alerts.enabled=true

# Custom webhook for server certificates
ca.notification.webhook.instance.cmdb.url=https://cmdb.example.com/api/pki/webhook
ca.notification.webhook.instance.cmdb.events=issued,revoked,expired
ca.notification.webhook.instance.cmdb.deviceTypes=server,container
ca.notification.webhook.instance.cmdb.secret=cmdb-webhook-secret
ca.notification.webhook.instance.cmdb.enabled=true
```

---

## Dashboard REST API

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ca/v2/dashboard/overview` | GET | Summary statistics for current user |
| `/ca/v2/dashboard/certificates` | GET | List user's certificates (paginated) |
| `/ca/v2/dashboard/requests` | GET | List user's certificate requests |
| `/ca/v2/dashboard/expiring` | GET | Certificates expiring within N days |
| `/ca/v2/dashboard/activity` | GET | Recent activity for user |

### Query Parameters

#### `/certificates`
- `status`: Filter by status (all, valid, expired, revoked)
- `deviceType`: Filter by device type
- `start`: Pagination start index
- `size`: Page size (default: 20)

#### `/expiring`
- `days`: Expiration window in days (default: 90)

#### `/requests`
- `status`: Filter by status (all, pending, approved, rejected)
- `start`: Pagination start index
- `size`: Page size

### Response Examples

#### Overview Response
```json
{
  "userId": "jsmith",
  "activeCertificates": 12,
  "expiredCertificates": 2,
  "revokedCertificates": 1,
  "expiringSoonCertificates": 3,
  "pendingRequests": 2
}
```

#### Certificates Response
```json
[
  {
    "serialNumber": "12345",
    "serialNumberHex": "0x3039",
    "subjectDN": "CN=web-server-01.example.com",
    "issuerDN": "CN=Example CA",
    "status": "VALID",
    "daysUntilExpiry": 45,
    "deviceType": "server",
    "deviceId": "web-01",
    "deviceGroup": "production"
  }
]
```

---

## Access Control

### Security Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                    ACCESS CONTROL LAYERS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Layer 1: AUTHENTICATION                                         │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ • Client Certificate (mutual TLS)                           ││
│  │ • Username/Password (LDAP)                                  ││
│  │ • External SSO (OIDC/SAML via reverse proxy)               ││
│  │ • API Token (for automation)                                ││
│  └─────────────────────────────────────────────────────────────┘│
│                           ↓                                      │
│  Layer 2: SESSION & IDENTITY                                     │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ SessionContext stores:                                      ││
│  │ • USER_ID: "jsmith"                                         ││
│  │ • USER_DN: "uid=jsmith,ou=people,o=pki-tomcat"             ││
│  │ • GROUPS: ["users", "developers"]                           ││
│  │ • AUTH_METHOD: "certUserDBAuth"                             ││
│  └─────────────────────────────────────────────────────────────┘│
│                           ↓                                      │
│  Layer 3: RESOURCE OWNERSHIP                                     │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Every resource has an OWNER:                                ││
│  │ • Certificate → requestor_userid from enrollment            ││
│  │ • Request → auth_token.userid at submission                 ││
│  │ • Webhook → configured admin only                           ││
│  └─────────────────────────────────────────────────────────────┘│
│                           ↓                                      │
│  Layer 4: AUTHORIZATION (ACL)                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Rules:                                                      ││
│  │ • Users can READ own resources                              ││
│  │ • Users can RENEW/REVOKE own certificates                   ││
│  │ • Agents can READ/APPROVE any pending request               ││
│  │ • Admins can READ/MODIFY any resource                       ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Request Flow

```
1. User Request
   └──▶ GET /ca/v2/dashboard/certificates

2. DashboardAuthMethod Filter
   └──▶ Validates authentication (cert/password/SSO)
   └──▶ Populates SessionContext with USER_ID
   └──▶ Rejects if not authenticated → 401

3. DashboardACL Filter
   └──▶ Checks ACL: certServer.ee.dashboard,read
   └──▶ All authenticated users pass (EE access)
   └──▶ Rejects if ACL fails → 403

4. DashboardServlet
   └──▶ getCurrentUserId() from SessionContext
   └──▶ findUserCertificates(userId) - OWNER FILTERING
   └──▶ Returns ONLY user's own data

5. Response
   └──▶ JSON with user's certificates only
```

### ACL Configuration

Add to `acl.properties`:

```properties
# Dashboard (user self-service)
dashboard = certServer.ee.dashboard,read
dashboard.certificates = certServer.ee.dashboard,read
dashboard.requests = certServer.ee.dashboard,read
dashboard.expiring = certServer.ee.dashboard,read
dashboard.activity = certServer.ee.dashboard,read
```

---

## Frontend UI

### Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  PKI Dashboard                         [John Smith ▼] [Notifications] [Logout]│
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ 12          │ │ 3           │ │ 1           │ │ 5           │           │
│  │ Active      │ │ Pending     │ │ Revoked     │ │ Expiring    │           │
│  │ Certificates│ │ Requests    │ │ Certificates│ │ Soon        │           │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘           │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ MY CERTIFICATES                                    [+ Request New]      ││
│  ├─────────────────────────────────────────────────────────────────────────┤│
│  │ Filter: [All Types ▼] [All Status ▼] [Search...]                       ││
│  ├──────┬──────────────────────┬─────────┬────────────┬────────┬──────────┤│
│  │ Type │ Subject              │ Device  │ Expires    │ Status │ Actions  ││
│  ├──────┼──────────────────────┼─────────┼────────────┼────────┼──────────┤│
│  │ 🖥️   │ web-server-01.corp   │ server  │ 2025-03-15 │ Valid  │ ⊕ ↓ 🔄   ││
│  │ 📱   │ mobile-app.corp      │ mobile  │ 2025-01-20 │ Warn   │ ⊕ ↓ 🔄   ││
│  │ 🔌   │ sensor-001.iot       │ iot     │ 2024-12-01 │ Exp    │ ⊕ ↓ 🔄   ││
│  └──────┴──────────────────────┴─────────┴────────────┴────────┴──────────┘│
│                                                                             │
│  ┌──────────────────────────────────┐ ┌────────────────────────────────────┐│
│  │ PENDING REQUESTS                 │ │ RECENT ACTIVITY                    ││
│  ├──────────────────────────────────┤ ├────────────────────────────────────┤│
│  │ api-gateway.corp                 │ │ ✓ Issued: web-server-01 (2h ago)  ││
│  │   Submitted: 2024-01-14          │ │ ✓ Renewed: db-server-02 (1d ago)  ││
│  │   Status: Awaiting Approval      │ │ ⚠ Revoked: old-app.corp (3d ago)  ││
│  └──────────────────────────────────┘ └────────────────────────────────────┘│
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ EXPIRATION TIMELINE                                                     ││
│  │ ═══════════●════════●═══════════●═══════════════════●══════════════>   ││
│  │         7 days    30 days     90 days            180 days              ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

- **CSS Framework**: PatternFly 4 (Red Hat design system)
- **JavaScript**: Vanilla JS (can be migrated to React)
- **Responsive**: Mobile-friendly design
- **No Build Required**: Single HTML file with embedded CSS/JS

### Access URL

```
https://<hostname>:8443/ca/dashboard/
```

---

## Device Metadata

### Supported Device Types

| Type | Description | Use Case |
|------|-------------|----------|
| `server` | Traditional servers | Web servers, databases |
| `iot` | IoT devices | Sensors, actuators |
| `mobile` | Mobile devices | Phones, tablets |
| `workstation` | Desktops/laptops | Employee workstations |
| `network` | Network equipment | Routers, switches |
| `container` | Containers/K8s | Microservices |
| `service` | Service accounts | Applications, APIs |

### Profile Input Configuration

Add `DeviceInfoInput` to enrollment profiles:

```
input.i10.class_id=deviceInfoInputImpl
```

### Metadata Fields

| Field | Description |
|-------|-------------|
| `deviceType` | Type of device (server, iot, mobile, etc.) |
| `deviceId` | Unique device identifier |
| `deviceGroup` | Logical grouping (e.g., "production", "factory-floor") |
| `deviceEnvironment` | Environment (production, staging, development, test) |
| `deviceLocation` | Physical or logical location |
| `deviceOwner` | Owner/team responsible |

---

## Configuration

### Complete CS.cfg Example

```properties
# =============================================================================
# Webhook Configuration
# =============================================================================

# Enable webhook notifications
ca.notification.webhook.enable=true
ca.notification.webhook.threadPoolSize=5

# Slack webhook
ca.notification.webhook.instance.slack.url=https://hooks.slack.com/services/XXX
ca.notification.webhook.instance.slack.events=issued,revoked,rejected,renewed
ca.notification.webhook.instance.slack.deviceTypes=*
ca.notification.webhook.instance.slack.secret=slack-webhook-secret
ca.notification.webhook.instance.slack.timeout=30
ca.notification.webhook.instance.slack.retries=3
ca.notification.webhook.instance.slack.enabled=true

# IoT alerts
ca.notification.webhook.instance.iot.url=https://iot-platform.example.com/webhook
ca.notification.webhook.instance.iot.events=issued,revoked,expired
ca.notification.webhook.instance.iot.deviceTypes=iot,network
ca.notification.webhook.instance.iot.timeout=15
ca.notification.webhook.instance.iot.enabled=true

# =============================================================================
# Dashboard Configuration
# =============================================================================

# Enable storing user ID in certificate metadata
ca.request.storeUserId=true
ca.cert.storeRequestorInfo=true

# Expiration warning thresholds
ca.dashboard.expiringSoonDays=30
ca.dashboard.expiringWarningDays=90
```

### ACL Configuration (acl.properties)

```properties
# Dashboard (user self-service)
dashboard = certServer.ee.dashboard,read
dashboard.certificates = certServer.ee.dashboard,read
dashboard.requests = certServer.ee.dashboard,read
dashboard.expiring = certServer.ee.dashboard,read
dashboard.activity = certServer.ee.dashboard,read
```

---

## Files Created

### Webhook Components

| File | Description |
|------|-------------|
| `base/ca/src/main/java/com/netscape/cms/listeners/WebhookListener.java` | Main listener class |
| `base/ca/src/main/java/com/netscape/cms/listeners/WebhookConfig.java` | Webhook configuration |
| `base/ca/src/main/java/com/netscape/cms/listeners/WebhookPayload.java` | JSON payload structure |
| `base/ca/src/main/java/com/netscape/cms/listeners/WebhookDispatcher.java` | Async HTTP dispatcher |

### Dashboard Components

| File | Description |
|------|-------------|
| `base/ca/src/main/java/org/dogtagpki/server/ca/rest/v2/DashboardServlet.java` | REST API servlet |
| `base/ca/src/main/java/org/dogtagpki/server/ca/rest/v2/filters/DashboardACL.java` | ACL filter |
| `base/ca/src/main/java/org/dogtagpki/server/ca/rest/v2/filters/DashboardAuthMethod.java` | Auth filter |
| `base/ca/shared/webapps/ca/dashboard/index.html` | Frontend UI |

### Profile Input

| File | Description |
|------|-------------|
| `base/ca/src/main/java/com/netscape/cms/profile/input/DeviceInfoInput.java` | Device metadata input |

### Modified Files

| File | Changes |
|------|---------|
| `base/ca/src/main/java/org/dogtagpki/server/ca/CAEngine.java` | Added webhook listener init |
| `base/server/src/main/resources/UserMessages.properties` | Added localized messages |
| `base/ca/shared/conf/acl.properties` | Added dashboard ACLs |

---

## Storage Backend

### Architecture Overview

The dashboard leverages a dual-database architecture for optimal performance:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Dashboard Storage Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│   ┌───────────────────────────────────────────────────────────────────────┐  │
│   │                         Redis (Cache Layer)                            │  │
│   │                                                                        │  │
│   │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│   │  │ Session Cache    │  │ Dashboard Stats  │  │ User Preferences     │ │  │
│   │  │ TTL: 30 min      │  │ TTL: 5 min       │  │ TTL: 24 hours        │ │  │
│   │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│   │                                                                        │  │
│   │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│   │  │ Rate Limiting    │  │ Recent Activity  │  │ Expiration Alerts    │ │  │
│   │  │ per-user/IP      │  │ TTL: 15 min      │  │ TTL: 1 hour          │ │  │
│   │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│   └───────────────────────────────────────────────────────────────────────┘  │
│                                    │                                          │
│                            cache miss                                         │
│                                    ▼                                          │
│   ┌───────────────────────────────────────────────────────────────────────┐  │
│   │                    PostgreSQL (Primary Storage)                        │  │
│   │                                                                        │  │
│   │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│   │  │ certificates     │  │ requests         │  │ users                │ │  │
│   │  │ - owner_id       │  │ - requestor_id   │  │ - user_id            │ │  │
│   │  │ - device_type    │  │ - status         │  │ - preferences_json   │ │  │
│   │  │ - expires_at     │  │ - created_at     │  │ - last_login         │ │  │
│   │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│   │                                                                        │  │
│   │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│   │  │ audit_log        │  │ webhook_delivery │  │ notifications        │ │  │
│   │  │ - action         │  │ - status         │  │ - user_id            │ │  │
│   │  │ - user_id        │  │ - attempts       │  │ - read               │ │  │
│   │  │ - timestamp      │  │ - last_attempt   │  │ - created_at         │ │  │
│   │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│   └───────────────────────────────────────────────────────────────────────┘  │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### PostgreSQL Schema (Dashboard-specific tables)

```sql
-- User dashboard preferences
CREATE TABLE dashboard_preferences (
    user_id VARCHAR(255) PRIMARY KEY,
    default_view VARCHAR(50) DEFAULT 'overview',
    items_per_page INTEGER DEFAULT 20,
    expiration_warning_days INTEGER DEFAULT 30,
    notification_settings JSONB,
    theme VARCHAR(20) DEFAULT 'light',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- User notifications (in-app)
CREATE TABLE dashboard_notifications (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT,
    link VARCHAR(500),
    read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    CONSTRAINT fk_user FOREIGN KEY (user_id)
        REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX idx_notifications_user_unread
    ON dashboard_notifications(user_id, read)
    WHERE read = FALSE;

-- Dashboard activity feed cache
CREATE TABLE dashboard_activity (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_activity_user_time
    ON dashboard_activity(user_id, timestamp DESC);
```

### Redis Key Patterns

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `session:{token}` | Session data with user info | 30 min |
| `dashboard:stats:{user_id}` | Cached overview statistics | 5 min |
| `dashboard:certs:{user_id}:{page}` | Cached certificate list page | 2 min |
| `dashboard:expiring:{user_id}` | Expiring certificates cache | 15 min |
| `dashboard:activity:{user_id}` | Recent activity feed | 10 min |
| `ratelimit:dashboard:{user_id}` | API rate limiting counter | 1 min |
| `prefs:{user_id}` | User preferences cache | 24 hours |

### Query Optimization

The dashboard uses PostgreSQL indexes for efficient user-scoped queries:

```sql
-- Efficient certificate lookup by owner
CREATE INDEX idx_certs_owner_status
    ON certificates(owner_id, status, expires_at);

-- Efficient request lookup by requestor
CREATE INDEX idx_requests_requestor_status
    ON requests(requestor_id, status, created_at DESC);

-- Device type filtering
CREATE INDEX idx_certs_device_type
    ON certificates(device_type)
    WHERE device_type IS NOT NULL;
```

### Cache Strategy

1. **Cache-aside pattern**: Dashboard reads from Redis first, falls back to PostgreSQL on miss
2. **Write-through**: Certificate events update both PostgreSQL and invalidate Redis cache
3. **TTL-based expiration**: Stale data automatically expires, no manual invalidation needed
4. **Pre-warming**: Popular dashboard views pre-cached on user login

---

## Future Enhancements

1. **React/TypeScript UI**: Migrate to modern React with TypeScript for better maintainability
2. **SSO/OIDC Integration**: Add OpenID Connect authentication support
3. **Bulk Operations**: Allow bulk renewal/revocation of certificates
4. **Email Notifications**: Expiration reminder emails
5. **Audit Dashboard**: View audit logs for own certificates
6. **API Tokens**: Personal API tokens for automation
7. **Certificate Templates**: User-defined enrollment templates
8. **Mobile App**: Native mobile application for certificate management

---

## Testing

### Webhook Testing

```bash
# Test webhook endpoint
curl -X POST https://webhook.example.com/test \
  -H "Content-Type: application/json" \
  -H "X-PKI-Signature-256: sha256=<signature>" \
  -d '{"event":"test","timestamp":"2024-01-15T10:00:00Z"}'
```

### Dashboard API Testing

```bash
# Get overview (requires authentication)
curl -k --cert admin.pem \
  https://localhost:8443/ca/v2/dashboard/overview

# Get certificates
curl -k --cert user.pem \
  https://localhost:8443/ca/v2/dashboard/certificates

# Get expiring certificates
curl -k --cert user.pem \
  "https://localhost:8443/ca/v2/dashboard/expiring?days=30"
```

---

## References

- [Dogtag PKI Documentation](https://github.com/dogtagpki/pki/wiki)
- [PatternFly Design System](https://www.patternfly.org/)
- [RFC 5280 - X.509 PKI](https://tools.ietf.org/html/rfc5280)

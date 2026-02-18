# PKI Webhook Notification System

This document describes the webhook notification system for Dogtag PKI certificate lifecycle events.

## Overview

The webhook system provides event-driven notifications for certificate lifecycle events, enabling integration with external systems like Slack, Microsoft Teams, ServiceNow, and custom monitoring platforms.

## Features

- **Event-driven notifications** for certificate issuance, renewal, revocation, and expiration
- **Device-type filtering** to route notifications based on certificate metadata
- **HMAC-SHA256 signing** for payload verification
- **Async delivery** with configurable retry and exponential backoff
- **Multiple webhook endpoints** with independent configuration

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Dogtag PKI CA                             │
│                                                                  │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐ │
│  │  Enrollment │───▶│  Request Queue   │───▶│ RequestNotifier │ │
│  │   Profile   │    │  (state engine)  │    │   (listeners)   │ │
│  └─────────────┘    └──────────────────┘    └────────┬────────┘ │
│                                                      │          │
│                                                      ▼          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    WebhookListener                         │  │
│  │                                                            │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │  │
│  │  │ Event Type   │  │ Device Type  │  │ Webhook Config   │ │  │
│  │  │ Detection    │  │ Filtering    │  │ Matching         │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘ │  │
│  │                           │                                │  │
│  │                           ▼                                │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              WebhookDispatcher                       │  │  │
│  │  │  • Async thread pool                                 │  │  │
│  │  │  • HMAC-SHA256 signing                               │  │  │
│  │  │  • Retry with exponential backoff                    │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
└──────────────────────────────┼───────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
    ┌──────────┐        ┌──────────┐         ┌──────────┐
    │  Slack   │        │  Teams   │         │  Custom  │
    │ Webhook  │        │ Webhook  │         │ Webhook  │
    └──────────┘        └──────────┘         └──────────┘
```

---

## Components

### Files Created

| File | Description |
|------|-------------|
| `base/ca/src/main/java/com/netscape/cms/listeners/WebhookListener.java` | Main listener that triggers on certificate events |
| `base/ca/src/main/java/com/netscape/cms/listeners/WebhookConfig.java` | Configuration for individual webhook endpoints |
| `base/ca/src/main/java/com/netscape/cms/listeners/WebhookPayload.java` | JSON payload structure sent to webhooks |
| `base/ca/src/main/java/com/netscape/cms/listeners/WebhookDispatcher.java` | Async HTTP dispatcher with retry and signing |
| `base/ca/src/main/java/com/netscape/cms/profile/input/DeviceInfoInput.java` | Profile input for device metadata |

### Modified Files

| File | Changes |
|------|---------|
| `base/ca/src/main/java/org/dogtagpki/server/ca/CAEngine.java` | Added webhook listener initialization |
| `base/server/src/main/resources/UserMessages.properties` | Added localized messages for device info |

---

## Supported Events

| Event | Description | Trigger |
|-------|-------------|---------|
| `certificate.issued` | New certificate issued | Enrollment request completed |
| `certificate.renewed` | Certificate renewed | Renewal request completed |
| `certificate.revoked` | Certificate revoked | Revocation request completed |
| `certificate.rejected` | Request rejected | Agent rejected enrollment |
| `certificate.pending` | Request pending | Request awaiting approval |

---

## Webhook Payload

### JSON Structure

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

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `event` | string | Event type (e.g., "certificate.issued") |
| `timestamp` | string | ISO 8601 timestamp in UTC |
| `instanceId` | string | PKI instance identifier |
| `certificate.serialNumber` | string | Decimal serial number |
| `certificate.serialNumberHex` | string | Hex serial number with 0x prefix |
| `certificate.subjectDN` | string | Certificate subject DN |
| `certificate.issuerDN` | string | Certificate issuer DN |
| `certificate.notBefore` | string | Validity start date |
| `certificate.notAfter` | string | Validity end date |
| `certificate.profileId` | string | Enrollment profile used |
| `device.type` | string | Device type (server, iot, mobile, etc.) |
| `device.id` | string | Device identifier |
| `device.group` | string | Device group/category |
| `request.id` | string | Certificate request ID |
| `request.type` | string | Request type (enrollment, renewal) |
| `request.status` | string | Request status |
| `request.requestorName` | string | Name of requestor |
| `request.requestorEmail` | string | Email of requestor |

---

## HTTP Headers

The webhook dispatcher sends the following headers with each request:

| Header | Description | Example |
|--------|-------------|---------|
| `Content-Type` | Payload content type | `application/json` |
| `User-Agent` | Identifying user agent | `Dogtag-PKI-Webhook/1.0` |
| `X-PKI-Event` | Event type | `certificate.issued` |
| `X-PKI-Delivery` | Unique delivery ID | `1705312200000-1` |
| `X-PKI-Timestamp` | Delivery timestamp (ms) | `1705312200000` |
| `X-PKI-Signature-256` | HMAC-SHA256 signature | `sha256=abc123...` |

---

## Security

### HMAC-SHA256 Signature Verification

When a webhook secret is configured, payloads are signed using HMAC-SHA256. The signature is included in the `X-PKI-Signature-256` header.

#### Verification Example (Python)

```python
import hmac
import hashlib

def verify_signature(payload_body, secret, signature_header):
    """Verify the webhook signature."""
    if not signature_header.startswith('sha256='):
        return False

    expected_signature = signature_header[7:]  # Remove 'sha256=' prefix

    computed_signature = hmac.new(
        secret.encode('utf-8'),
        payload_body.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(computed_signature, expected_signature)

# Usage
payload = '{"event":"certificate.issued",...}'
secret = 'my-webhook-secret'
signature = request.headers.get('X-PKI-Signature-256')

if verify_signature(payload, secret, signature):
    print("Signature valid!")
else:
    print("Invalid signature!")
```

#### Verification Example (Node.js)

```javascript
const crypto = require('crypto');

function verifySignature(payloadBody, secret, signatureHeader) {
    if (!signatureHeader.startsWith('sha256=')) {
        return false;
    }

    const expectedSignature = signatureHeader.slice(7);

    const computedSignature = crypto
        .createHmac('sha256', secret)
        .update(payloadBody)
        .digest('hex');

    return crypto.timingSafeEqual(
        Buffer.from(computedSignature),
        Buffer.from(expectedSignature)
    );
}
```

### Retry Logic

Failed deliveries are retried with exponential backoff:

| Attempt | Delay |
|---------|-------|
| 1 | Immediate |
| 2 | 1 second |
| 3 | 2 seconds |
| 4 | 4 seconds |
| 5+ | 8 seconds |

Successful delivery: HTTP status 2xx
Failed delivery: Any other status or connection error

---

## Device Types

The webhook system supports filtering by device type. Device metadata is captured during enrollment using the `DeviceInfoInput` profile input.

### Supported Device Types

| Type | Description | Example Use Cases |
|------|-------------|-------------------|
| `server` | Traditional servers | Web servers, databases, application servers |
| `iot` | IoT devices | Sensors, actuators, edge devices |
| `mobile` | Mobile devices | Smartphones, tablets |
| `workstation` | Desktop/laptop | Employee workstations |
| `network` | Network equipment | Routers, switches, firewalls |
| `container` | Containers/K8s | Docker, Kubernetes workloads |
| `service` | Service accounts | APIs, microservices, automation |
| `other` | Other devices | Miscellaneous |

### Device Metadata Fields

| Field | Description |
|-------|-------------|
| `deviceType` | Type of device |
| `deviceId` | Unique device identifier |
| `deviceGroup` | Logical grouping |
| `deviceEnvironment` | Environment (production, staging, dev, test) |
| `deviceLocation` | Physical or logical location |
| `deviceOwner` | Owner or responsible team |

---

## Configuration

### Enable Webhooks

Add to `CS.cfg`:

```properties
# Enable webhook notifications
ca.notification.webhook.enable=true

# Thread pool size for async delivery
ca.notification.webhook.threadPoolSize=5
```

### Configure Webhook Endpoints

Each webhook endpoint is configured as an instance:

```properties
# Webhook instance: <name>
ca.notification.webhook.instance.<name>.url=<webhook-url>
ca.notification.webhook.instance.<name>.events=<event-list>
ca.notification.webhook.instance.<name>.deviceTypes=<device-type-list>
ca.notification.webhook.instance.<name>.secret=<hmac-secret>
ca.notification.webhook.instance.<name>.timeout=<seconds>
ca.notification.webhook.instance.<name>.retries=<count>
ca.notification.webhook.instance.<name>.enabled=<true|false>
ca.notification.webhook.instance.<name>.contentType=<content-type>
```

### Configuration Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `url` | Yes | - | Webhook endpoint URL |
| `events` | No | `issued,revoked,rejected` | Comma-separated event list |
| `deviceTypes` | No | `*` | Comma-separated device types, or `*` for all |
| `secret` | No | - | HMAC-SHA256 signing secret |
| `timeout` | No | `30` | Connection timeout in seconds |
| `retries` | No | `3` | Number of retry attempts |
| `enabled` | No | `true` | Enable/disable this webhook |
| `contentType` | No | `application/json` | Content-Type header |

---

## Configuration Examples

### Slack Integration

```properties
ca.notification.webhook.instance.slack.url=https://example.com/slack-webhook-endpoint
ca.notification.webhook.instance.slack.events=issued,revoked,rejected,renewed
ca.notification.webhook.instance.slack.deviceTypes=*
ca.notification.webhook.instance.slack.secret=slack-signing-secret
ca.notification.webhook.instance.slack.timeout=30
ca.notification.webhook.instance.slack.retries=3
ca.notification.webhook.instance.slack.enabled=true
```

### Microsoft Teams Integration

```properties
ca.notification.webhook.instance.teams.url=https://outlook.office.com/webhook/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ca.notification.webhook.instance.teams.events=revoked,expired
ca.notification.webhook.instance.teams.deviceTypes=server,network
ca.notification.webhook.instance.teams.timeout=15
ca.notification.webhook.instance.teams.enabled=true
```

### IoT Platform Integration

```properties
ca.notification.webhook.instance.iot-platform.url=https://iot.example.com/api/pki/events
ca.notification.webhook.instance.iot-platform.events=issued,revoked,expired
ca.notification.webhook.instance.iot-platform.deviceTypes=iot,network
ca.notification.webhook.instance.iot-platform.secret=iot-webhook-secret
ca.notification.webhook.instance.iot-platform.timeout=10
ca.notification.webhook.instance.iot-platform.retries=5
ca.notification.webhook.instance.iot-platform.enabled=true
```

### ServiceNow CMDB Integration

```properties
ca.notification.webhook.instance.servicenow.url=https://instance.service-now.com/api/now/table/cmdb_ci_certificate
ca.notification.webhook.instance.servicenow.events=issued,revoked,renewed,expired
ca.notification.webhook.instance.servicenow.deviceTypes=server,container
ca.notification.webhook.instance.servicenow.secret=servicenow-api-key
ca.notification.webhook.instance.servicenow.timeout=30
ca.notification.webhook.instance.servicenow.enabled=true
```

### Multiple Webhooks Example

```properties
# Global settings
ca.notification.webhook.enable=true
ca.notification.webhook.threadPoolSize=10

# Slack - all events
ca.notification.webhook.instance.slack.url=https://hooks.slack.com/services/XXX
ca.notification.webhook.instance.slack.events=*
ca.notification.webhook.instance.slack.deviceTypes=*
ca.notification.webhook.instance.slack.enabled=true

# PagerDuty - revocations only
ca.notification.webhook.instance.pagerduty.url=https://events.pagerduty.com/v2/enqueue
ca.notification.webhook.instance.pagerduty.events=revoked
ca.notification.webhook.instance.pagerduty.deviceTypes=server,network
ca.notification.webhook.instance.pagerduty.secret=pagerduty-routing-key
ca.notification.webhook.instance.pagerduty.enabled=true

# IoT platform - IoT devices only
ca.notification.webhook.instance.iot.url=https://iot.example.com/webhook
ca.notification.webhook.instance.iot.events=issued,revoked
ca.notification.webhook.instance.iot.deviceTypes=iot
ca.notification.webhook.instance.iot.enabled=true

# SIEM - all security events
ca.notification.webhook.instance.siem.url=https://siem.example.com/api/events
ca.notification.webhook.instance.siem.events=issued,revoked,rejected
ca.notification.webhook.instance.siem.deviceTypes=*
ca.notification.webhook.instance.siem.secret=siem-api-token
ca.notification.webhook.instance.siem.enabled=true
```

---

## Profile Configuration

To capture device metadata during enrollment, add the `DeviceInfoInput` to your enrollment profiles.

### Add to Profile

```properties
input.i10.class_id=deviceInfoInputImpl
```

### Available Input Fields

The `DeviceInfoInput` provides these fields on the enrollment form:

| Field | Type | Description |
|-------|------|-------------|
| `deviceType` | Dropdown | Device type selection |
| `deviceId` | Text | Device identifier |
| `deviceGroup` | Text | Device group/category |
| `deviceEnvironment` | Dropdown | Environment selection |
| `deviceLocation` | Text | Location |
| `deviceOwner` | Text | Owner/team |

---

## Testing

### Test Webhook Endpoint

```bash
# Send a test webhook manually
curl -X POST https://your-webhook-endpoint.com/webhook \
  -H "Content-Type: application/json" \
  -H "X-PKI-Event: test" \
  -H "X-PKI-Delivery: test-$(date +%s)" \
  -H "X-PKI-Timestamp: $(date +%s)000" \
  -d '{
    "event": "test",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "instanceId": "pki-tomcat"
  }'
```

### Test with Signature

```bash
# Generate HMAC signature
SECRET="my-webhook-secret"
PAYLOAD='{"event":"test","timestamp":"2024-01-15T10:00:00Z"}'
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)

curl -X POST https://your-webhook-endpoint.com/webhook \
  -H "Content-Type: application/json" \
  -H "X-PKI-Signature-256: sha256=$SIGNATURE" \
  -d "$PAYLOAD"
```

### Local Testing with netcat

```bash
# Start a simple listener
nc -l 8080

# In another terminal, trigger a certificate event
# The webhook payload will appear in the netcat output
```

### Webhook Debugging

Enable debug logging in `logging.properties`:

```properties
log4j.logger.com.netscape.cms.listeners.WebhookListener=DEBUG
log4j.logger.com.netscape.cms.listeners.WebhookDispatcher=DEBUG
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Webhooks not firing | Not enabled | Set `ca.notification.webhook.enable=true` |
| Signature verification fails | Wrong secret | Verify secret matches on both ends |
| Connection timeout | Network/firewall | Check connectivity, increase timeout |
| 401/403 errors | Authentication required | Add auth headers or use secret |
| Retries exhausted | Endpoint unavailable | Check endpoint health, increase retries |

### Log Messages

| Message | Level | Meaning |
|---------|-------|---------|
| `WebhookListener: Initialized with N webhook(s)` | INFO | Successful initialization |
| `WebhookListener: Sending to webhook X for event Y` | INFO | Webhook triggered |
| `WebhookDispatcher: Successfully delivered to X` | INFO | Successful delivery |
| `WebhookDispatcher: Failed to deliver to X after N attempts` | ERROR | All retries failed |
| `WebhookListener: No webhook configuration found` | INFO | No webhooks configured |

---

## API Reference

### WebhookListener

```java
public class WebhookListener extends RequestListener {
    // Event types
    public static final String EVENT_ISSUED = "issued";
    public static final String EVENT_REVOKED = "revoked";
    public static final String EVENT_REJECTED = "rejected";
    public static final String EVENT_PENDING = "pending";
    public static final String EVENT_RENEWED = "renewed";
    public static final String EVENT_EXPIRED = "expired";

    // Device metadata keys
    public static final String META_DEVICE_TYPE = "deviceType";
    public static final String META_DEVICE_ID = "deviceId";
    public static final String META_DEVICE_GROUP = "deviceGroup";

    // Main callback method
    public void accept(Request request);

    // Get configured webhooks
    public List<WebhookConfig> getWebhooks();

    // Check if enabled
    public boolean isEnabled();
}
```

### WebhookConfig

```java
public class WebhookConfig {
    public String getName();
    public String getUrl();
    public Set<String> getEvents();
    public Set<String> getDeviceTypes();
    public String getSecret();
    public int getTimeout();
    public int getRetries();
    public boolean isEnabled();
    public String getContentType();

    // Matching methods
    public boolean matchesEvent(String eventType);
    public boolean matchesDeviceType(String deviceType);
}
```

### WebhookDispatcher

```java
public class WebhookDispatcher {
    // HTTP headers
    public static final String HEADER_SIGNATURE = "X-PKI-Signature-256";
    public static final String HEADER_EVENT = "X-PKI-Event";
    public static final String HEADER_DELIVERY_ID = "X-PKI-Delivery";
    public static final String HEADER_TIMESTAMP = "X-PKI-Timestamp";

    // Dispatch webhook asynchronously
    public void dispatch(WebhookConfig webhook, WebhookPayload payload);

    // Test webhook endpoint
    public boolean testWebhook(WebhookConfig webhook);

    // Shutdown dispatcher
    public void shutdown();
}
```

---

## References

- [GitHub Webhooks Documentation](https://docs.github.com/en/webhooks)
- [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
- [Microsoft Teams Webhooks](https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
- [RFC 2104 - HMAC](https://tools.ietf.org/html/rfc2104)

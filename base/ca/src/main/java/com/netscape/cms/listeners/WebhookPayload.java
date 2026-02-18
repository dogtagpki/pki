// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2024 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.listeners;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Webhook payload for certificate lifecycle events.
 *
 * Example JSON output:
 * {
 *   "event": "certificate.issued",
 *   "timestamp": "2024-01-15T10:30:00Z",
 *   "instanceId": "pki-tomcat",
 *   "certificate": {
 *     "serialNumber": "12345",
 *     "serialNumberHex": "0x3039",
 *     "subjectDN": "CN=example.com",
 *     "issuerDN": "CN=CA Signing Certificate",
 *     "notBefore": "2024-01-15",
 *     "notAfter": "2025-01-15",
 *     "profileId": "caServerCert"
 *   },
 *   "device": {
 *     "type": "server",
 *     "id": "web-server-01",
 *     "group": "production"
 *   },
 *   "request": {
 *     "id": "123",
 *     "type": "enrollment",
 *     "status": "complete",
 *     "requestorName": "admin",
 *     "requestorEmail": "admin@example.com"
 *   }
 * }
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WebhookPayload {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final SimpleDateFormat ISO_FORMAT;

    static {
        ISO_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        ISO_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    // Event info
    private String event;
    private String timestamp;
    private String instanceId;

    // Certificate info
    private String serialNumber;
    private String serialNumberHex;
    private String subjectDN;
    private String issuerDN;
    private String notBefore;
    private String notAfter;
    private String profileId;

    // Device metadata
    private String deviceType;
    private String deviceId;
    private String deviceGroup;

    // Request info
    private String requestId;
    private String requestType;
    private String requestStatus;
    private String requestorName;
    private String requestorEmail;

    public WebhookPayload() {
    }

    // Event setters

    public void setEvent(String event) {
        this.event = event;
    }

    public void setTimestamp(Date timestamp) {
        if (timestamp != null) {
            synchronized (ISO_FORMAT) {
                this.timestamp = ISO_FORMAT.format(timestamp);
            }
        }
    }

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    // Certificate setters

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public void setSerialNumberHex(String serialNumberHex) {
        this.serialNumberHex = serialNumberHex;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    // Device setters

    public void setDeviceType(String deviceType) {
        this.deviceType = deviceType;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public void setDeviceGroup(String deviceGroup) {
        this.deviceGroup = deviceGroup;
    }

    // Request setters

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    public void setRequestStatus(String requestStatus) {
        this.requestStatus = requestStatus;
    }

    public void setRequestorName(String requestorName) {
        this.requestorName = requestorName;
    }

    public void setRequestorEmail(String requestorEmail) {
        this.requestorEmail = requestorEmail;
    }

    // Getters for JSON serialization

    @JsonProperty("event")
    public String getEvent() {
        return event;
    }

    @JsonProperty("timestamp")
    public String getTimestamp() {
        return timestamp;
    }

    @JsonProperty("instanceId")
    public String getInstanceId() {
        return instanceId;
    }

    @JsonProperty("certificate")
    public CertificateInfo getCertificate() {
        if (serialNumber == null && subjectDN == null) {
            return null;
        }
        return new CertificateInfo();
    }

    @JsonProperty("device")
    public DeviceInfo getDevice() {
        if (deviceType == null && deviceId == null && deviceGroup == null) {
            return null;
        }
        return new DeviceInfo();
    }

    @JsonProperty("request")
    public RequestInfo getRequest() {
        return new RequestInfo();
    }

    /**
     * Convert payload to JSON string.
     */
    public String toJson() throws JsonProcessingException {
        return mapper.writeValueAsString(this);
    }

    /**
     * Convert payload to pretty-printed JSON string.
     */
    public String toJsonPretty() throws JsonProcessingException {
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(this);
    }

    // Nested classes for structured JSON output

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public class CertificateInfo {
        @JsonProperty("serialNumber")
        public String getSerialNumber() {
            return serialNumber;
        }

        @JsonProperty("serialNumberHex")
        public String getSerialNumberHex() {
            return serialNumberHex;
        }

        @JsonProperty("subjectDN")
        public String getSubjectDN() {
            return subjectDN;
        }

        @JsonProperty("issuerDN")
        public String getIssuerDN() {
            return issuerDN;
        }

        @JsonProperty("notBefore")
        public String getNotBefore() {
            return notBefore;
        }

        @JsonProperty("notAfter")
        public String getNotAfter() {
            return notAfter;
        }

        @JsonProperty("profileId")
        public String getProfileId() {
            return profileId;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public class DeviceInfo {
        @JsonProperty("type")
        public String getType() {
            return deviceType;
        }

        @JsonProperty("id")
        public String getId() {
            return deviceId;
        }

        @JsonProperty("group")
        public String getGroup() {
            return deviceGroup;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public class RequestInfo {
        @JsonProperty("id")
        public String getId() {
            return requestId;
        }

        @JsonProperty("type")
        public String getType() {
            return requestType;
        }

        @JsonProperty("status")
        public String getStatus() {
            return requestStatus;
        }

        @JsonProperty("requestorName")
        public String getRequestorName() {
            return requestorName;
        }

        @JsonProperty("requestorEmail")
        public String getRequestorEmail() {
            return requestorEmail;
        }
    }
}

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

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

/**
 * A listener that sends webhook notifications for certificate lifecycle events.
 *
 * Configuration in CS.cfg:
 *
 * ca.notification.webhook.enable=true
 * ca.notification.webhook.instance.mywebhook.url=https://example.com/webhook
 * ca.notification.webhook.instance.mywebhook.events=issued,revoked,rejected
 * ca.notification.webhook.instance.mywebhook.deviceTypes=server,iot,mobile
 * ca.notification.webhook.instance.mywebhook.secret=<hmac-secret>
 * ca.notification.webhook.instance.mywebhook.timeout=30
 * ca.notification.webhook.instance.mywebhook.retries=3
 */
public class WebhookListener extends RequestListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(WebhookListener.class);

    protected static final String PROP_WEBHOOK_SUBSTORE = "webhook";
    protected static final String PROP_ENABLED = "enable";
    protected static final String PROP_INSTANCE = "instance";

    // Event types
    public static final String EVENT_ISSUED = "issued";
    public static final String EVENT_REVOKED = "revoked";
    public static final String EVENT_REJECTED = "rejected";
    public static final String EVENT_PENDING = "pending";
    public static final String EVENT_RENEWED = "renewed";
    public static final String EVENT_EXPIRED = "expired";

    // Device type metadata key
    public static final String META_DEVICE_TYPE = "deviceType";
    public static final String META_DEVICE_ID = "deviceId";
    public static final String META_DEVICE_GROUP = "deviceGroup";

    private boolean mEnabled = false;
    private List<WebhookConfig> mWebhooks = new ArrayList<>();
    private WebhookDispatcher mDispatcher;
    private DateFormat mDateFormat = null;
    private String mInstanceId = null;

    public WebhookListener() {
    }

    @Override
    public void init(Subsystem sub, ConfigStore config) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        mInstanceId = cs.getInstanceID();
        mDateFormat = DateFormat.getDateTimeInstance();

        // Get webhook configuration substore
        ConfigStore webhookConfig = config.getSubStore(PROP_WEBHOOK_SUBSTORE, ConfigStore.class);
        if (webhookConfig == null || webhookConfig.size() == 0) {
            logger.info("WebhookListener: No webhook configuration found");
            return;
        }

        mEnabled = webhookConfig.getBoolean(PROP_ENABLED, false);
        if (!mEnabled) {
            logger.info("WebhookListener: Webhooks are disabled");
            return;
        }

        // Initialize dispatcher
        mDispatcher = new WebhookDispatcher();
        mDispatcher.init(webhookConfig);

        // Load webhook instances
        ConfigStore instanceConfig = webhookConfig.getSubStore(PROP_INSTANCE, ConfigStore.class);
        if (instanceConfig != null) {
            Enumeration<String> instanceNames = instanceConfig.getPropertyNames();
            List<String> loadedInstances = new ArrayList<>();

            while (instanceNames.hasMoreElements()) {
                String fullKey = instanceNames.nextElement();
                // Extract instance name (first part before the dot)
                String instanceName = fullKey.contains(".") ?
                        fullKey.substring(0, fullKey.indexOf('.')) : fullKey;

                if (!loadedInstances.contains(instanceName)) {
                    loadedInstances.add(instanceName);
                    try {
                        ConfigStore whConfig = instanceConfig.getSubStore(instanceName, ConfigStore.class);
                        WebhookConfig wh = new WebhookConfig(instanceName);
                        wh.init(whConfig);
                        mWebhooks.add(wh);
                        logger.info("WebhookListener: Loaded webhook instance: " + instanceName);
                    } catch (Exception e) {
                        logger.warn("WebhookListener: Failed to load webhook " + instanceName + ": " + e.getMessage());
                    }
                }
            }
        }

        logger.info("WebhookListener: Initialized with " + mWebhooks.size() + " webhook(s)");

        // Register this listener
        engine.registerRequestListener(this);
    }

    @Override
    public void accept(Request request) {
        if (!mEnabled) {
            return;
        }

        logger.debug("WebhookListener: Processing request " + request.getRequestId());

        String eventType = determineEventType(request);
        if (eventType == null) {
            logger.debug("WebhookListener: No event type determined for request");
            return;
        }

        String deviceType = getDeviceType(request);
        logger.debug("WebhookListener: Event=" + eventType + ", DeviceType=" + deviceType);

        // Build payload
        WebhookPayload payload = buildPayload(request, eventType);

        // Send to matching webhooks
        for (WebhookConfig webhook : mWebhooks) {
            if (webhook.matchesEvent(eventType) && webhook.matchesDeviceType(deviceType)) {
                logger.info("WebhookListener: Sending to webhook " + webhook.getName() +
                        " for event " + eventType);
                mDispatcher.dispatch(webhook, payload);
            }
        }
    }

    /**
     * Determine the event type from the request status and type.
     */
    private String determineEventType(Request request) {
        String status = request.getRequestStatus().toString();
        String requestType = request.getRequestType();

        if ("rejected".equals(status)) {
            return EVENT_REJECTED;
        }

        if ("pending".equals(status)) {
            return EVENT_PENDING;
        }

        if ("complete".equals(status)) {
            if (Request.ENROLLMENT_REQUEST.equals(requestType)) {
                return EVENT_ISSUED;
            } else if (Request.RENEWAL_REQUEST.equals(requestType)) {
                return EVENT_RENEWED;
            } else if (Request.REVOCATION_REQUEST.equals(requestType)) {
                return EVENT_REVOKED;
            }
        }

        return null;
    }

    /**
     * Get device type from request metadata.
     */
    private String getDeviceType(Request request) {
        String deviceType = request.getExtDataInString(META_DEVICE_TYPE);
        return deviceType != null ? deviceType : "unknown";
    }

    /**
     * Build the webhook payload from the request.
     */
    private WebhookPayload buildPayload(Request request, String eventType) {
        WebhookPayload payload = new WebhookPayload();

        payload.setEvent("certificate." + eventType);
        payload.setTimestamp(new Date());
        payload.setInstanceId(mInstanceId);

        // Request info
        payload.setRequestId(request.getRequestId().toString());
        payload.setRequestType(request.getRequestType());
        payload.setRequestStatus(request.getRequestStatus().toString());

        // Device metadata
        payload.setDeviceType(request.getExtDataInString(META_DEVICE_TYPE));
        payload.setDeviceId(request.getExtDataInString(META_DEVICE_ID));
        payload.setDeviceGroup(request.getExtDataInString(META_DEVICE_GROUP));

        // Profile info
        payload.setProfileId(request.getExtDataInString(Request.PROFILE_ID));

        // Certificate info (if available)
        X509CertImpl cert = null;
        String profileId = request.getExtDataInString(Request.PROFILE_ID);

        if (profileId != null) {
            cert = request.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
        } else {
            X509CertImpl[] certs = request.getExtDataInCertArray(Request.ISSUED_CERTS);
            if (certs != null && certs.length > 0) {
                cert = certs[0];
            }
        }

        if (cert != null) {
            payload.setSerialNumber(cert.getSerialNumber().toString());
            payload.setSerialNumberHex("0x" + cert.getSerialNumber().toString(16).toUpperCase());
            payload.setSubjectDN(cert.getSubjectName().toString());
            payload.setIssuerDN(cert.getIssuerName().toString());
            payload.setNotBefore(mDateFormat.format(cert.getNotBefore()));
            payload.setNotAfter(mDateFormat.format(cert.getNotAfter()));
        }

        // Requestor info
        payload.setRequestorName(request.getExtDataInString(Request.REQUESTOR_NAME));
        payload.setRequestorEmail(request.getExtDataInString(Request.REQUESTOR_EMAIL));

        return payload;
    }

    @Override
    public void set(String name, String val) {
        if (name.equalsIgnoreCase(PROP_ENABLED)) {
            mEnabled = "true".equalsIgnoreCase(val);
        } else {
            logger.warn("WebhookListener: Unknown property: " + name);
        }
    }

    /**
     * Get list of configured webhooks (for management/monitoring).
     */
    public List<WebhookConfig> getWebhooks() {
        return new ArrayList<>(mWebhooks);
    }

    /**
     * Check if webhooks are enabled.
     */
    public boolean isEnabled() {
        return mEnabled;
    }
}

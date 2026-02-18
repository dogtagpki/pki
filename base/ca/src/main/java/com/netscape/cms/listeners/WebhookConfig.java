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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStore;

/**
 * Configuration for a single webhook endpoint.
 *
 * Example configuration:
 *   url=https://example.com/webhook
 *   events=issued,revoked,rejected
 *   deviceTypes=server,iot,mobile (or * for all)
 *   secret=my-hmac-secret
 *   timeout=30
 *   retries=3
 *   enabled=true
 */
public class WebhookConfig {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(WebhookConfig.class);

    protected static final String PROP_URL = "url";
    protected static final String PROP_EVENTS = "events";
    protected static final String PROP_DEVICE_TYPES = "deviceTypes";
    protected static final String PROP_SECRET = "secret";
    protected static final String PROP_TIMEOUT = "timeout";
    protected static final String PROP_RETRIES = "retries";
    protected static final String PROP_ENABLED = "enabled";
    protected static final String PROP_CONTENT_TYPE = "contentType";
    protected static final String PROP_HEADERS = "headers";

    private String mName;
    private String mUrl;
    private Set<String> mEvents = new HashSet<>();
    private Set<String> mDeviceTypes = new HashSet<>();
    private String mSecret;
    private int mTimeout = 30; // seconds
    private int mRetries = 3;
    private boolean mEnabled = true;
    private String mContentType = "application/json";

    public WebhookConfig(String name) {
        this.mName = name;
    }

    public void init(ConfigStore config) throws EBaseException {
        mUrl = config.getString(PROP_URL, null);
        if (mUrl == null || mUrl.isEmpty()) {
            throw new EBaseException("Webhook URL is required for instance: " + mName);
        }

        // Parse events (comma-separated)
        String events = config.getString(PROP_EVENTS, "issued,revoked,rejected");
        for (String event : events.split(",")) {
            String trimmed = event.trim().toLowerCase();
            if (!trimmed.isEmpty()) {
                mEvents.add(trimmed);
            }
        }

        // Parse device types (comma-separated, * means all)
        String deviceTypes = config.getString(PROP_DEVICE_TYPES, "*");
        if ("*".equals(deviceTypes.trim())) {
            mDeviceTypes.add("*");
        } else {
            for (String deviceType : deviceTypes.split(",")) {
                String trimmed = deviceType.trim().toLowerCase();
                if (!trimmed.isEmpty()) {
                    mDeviceTypes.add(trimmed);
                }
            }
        }

        mSecret = config.getString(PROP_SECRET, null);
        mTimeout = config.getInteger(PROP_TIMEOUT, 30);
        mRetries = config.getInteger(PROP_RETRIES, 3);
        mEnabled = config.getBoolean(PROP_ENABLED, true);
        mContentType = config.getString(PROP_CONTENT_TYPE, "application/json");

        logger.debug("WebhookConfig: Initialized webhook " + mName +
                " url=" + mUrl +
                " events=" + mEvents +
                " deviceTypes=" + mDeviceTypes +
                " timeout=" + mTimeout +
                " retries=" + mRetries);
    }

    /**
     * Check if this webhook should be triggered for the given event.
     */
    public boolean matchesEvent(String eventType) {
        if (eventType == null) {
            return false;
        }
        return mEvents.contains("*") || mEvents.contains(eventType.toLowerCase());
    }

    /**
     * Check if this webhook should be triggered for the given device type.
     */
    public boolean matchesDeviceType(String deviceType) {
        if (mDeviceTypes.contains("*")) {
            return true;
        }
        if (deviceType == null || deviceType.isEmpty()) {
            deviceType = "unknown";
        }
        return mDeviceTypes.contains(deviceType.toLowerCase());
    }

    // Getters

    public String getName() {
        return mName;
    }

    public String getUrl() {
        return mUrl;
    }

    public Set<String> getEvents() {
        return new HashSet<>(mEvents);
    }

    public Set<String> getDeviceTypes() {
        return new HashSet<>(mDeviceTypes);
    }

    public String getSecret() {
        return mSecret;
    }

    public int getTimeout() {
        return mTimeout;
    }

    public int getRetries() {
        return mRetries;
    }

    public boolean isEnabled() {
        return mEnabled;
    }

    public String getContentType() {
        return mContentType;
    }

    @Override
    public String toString() {
        return "WebhookConfig{" +
                "name='" + mName + '\'' +
                ", url='" + mUrl + '\'' +
                ", events=" + mEvents +
                ", deviceTypes=" + mDeviceTypes +
                ", timeout=" + mTimeout +
                ", retries=" + mRetries +
                ", enabled=" + mEnabled +
                '}';
    }
}

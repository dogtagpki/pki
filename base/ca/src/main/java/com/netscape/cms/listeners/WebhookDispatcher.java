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

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStore;

/**
 * Asynchronous webhook dispatcher with retry support and HMAC signing.
 *
 * Sends webhook payloads to configured endpoints using HTTP POST.
 * Supports:
 * - Async dispatch via thread pool
 * - Configurable retry with exponential backoff
 * - HMAC-SHA256 signature for payload verification
 * - Timeout configuration
 */
public class WebhookDispatcher {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(WebhookDispatcher.class);

    protected static final String PROP_THREAD_POOL_SIZE = "threadPoolSize";
    protected static final String PROP_MAX_QUEUE_SIZE = "maxQueueSize";

    // Signature header name (similar to GitHub webhooks)
    public static final String HEADER_SIGNATURE = "X-PKI-Signature-256";
    public static final String HEADER_EVENT = "X-PKI-Event";
    public static final String HEADER_DELIVERY_ID = "X-PKI-Delivery";
    public static final String HEADER_TIMESTAMP = "X-PKI-Timestamp";

    private ExecutorService mExecutor;
    private int mThreadPoolSize = 5;
    private long mDeliveryCounter = 0;

    public WebhookDispatcher() {
    }

    public void init(ConfigStore config) throws EBaseException {
        mThreadPoolSize = config.getInteger(PROP_THREAD_POOL_SIZE, 5);
        mExecutor = Executors.newFixedThreadPool(mThreadPoolSize);
        logger.info("WebhookDispatcher: Initialized with thread pool size: " + mThreadPoolSize);
    }

    /**
     * Dispatch a webhook payload asynchronously.
     */
    public void dispatch(WebhookConfig webhook, WebhookPayload payload) {
        if (!webhook.isEnabled()) {
            logger.debug("WebhookDispatcher: Webhook " + webhook.getName() + " is disabled, skipping");
            return;
        }

        String deliveryId = generateDeliveryId();

        mExecutor.submit(() -> {
            deliverWithRetry(webhook, payload, deliveryId);
        });
    }

    /**
     * Deliver webhook with retry logic.
     */
    private void deliverWithRetry(WebhookConfig webhook, WebhookPayload payload, String deliveryId) {
        int retries = webhook.getRetries();
        int attempt = 0;
        boolean success = false;

        while (attempt <= retries && !success) {
            attempt++;
            try {
                int responseCode = deliver(webhook, payload, deliveryId, attempt);

                if (responseCode >= 200 && responseCode < 300) {
                    success = true;
                    logger.info("WebhookDispatcher: Successfully delivered to " + webhook.getName() +
                            " (attempt " + attempt + ", deliveryId=" + deliveryId + ")");
                } else {
                    logger.warn("WebhookDispatcher: Webhook " + webhook.getName() +
                            " returned status " + responseCode +
                            " (attempt " + attempt + "/" + (retries + 1) + ")");
                }

            } catch (Exception e) {
                logger.warn("WebhookDispatcher: Failed to deliver to " + webhook.getName() +
                        " (attempt " + attempt + "/" + (retries + 1) + "): " + e.getMessage());
            }

            if (!success && attempt <= retries) {
                // Exponential backoff: 1s, 2s, 4s, 8s, ...
                long backoffMs = (long) Math.pow(2, attempt - 1) * 1000;
                try {
                    Thread.sleep(backoffMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }

        if (!success) {
            logger.error("WebhookDispatcher: Failed to deliver to " + webhook.getName() +
                    " after " + (retries + 1) + " attempts (deliveryId=" + deliveryId + ")");
        }
    }

    /**
     * Perform the actual HTTP delivery.
     */
    private int deliver(WebhookConfig webhook, WebhookPayload payload, String deliveryId, int attempt)
            throws IOException {

        String jsonPayload;
        try {
            jsonPayload = payload.toJson();
        } catch (Exception e) {
            throw new IOException("Failed to serialize payload: " + e.getMessage(), e);
        }

        URL url = new URL(webhook.getUrl());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        try {
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(webhook.getTimeout() * 1000);
            conn.setReadTimeout(webhook.getTimeout() * 1000);

            // Set headers
            conn.setRequestProperty("Content-Type", webhook.getContentType());
            conn.setRequestProperty("User-Agent", "Dogtag-PKI-Webhook/1.0");
            conn.setRequestProperty(HEADER_EVENT, payload.getEvent());
            conn.setRequestProperty(HEADER_DELIVERY_ID, deliveryId);
            conn.setRequestProperty(HEADER_TIMESTAMP, String.valueOf(System.currentTimeMillis()));

            // Add HMAC signature if secret is configured
            String secret = webhook.getSecret();
            if (secret != null && !secret.isEmpty()) {
                String signature = computeHmacSignature(jsonPayload, secret);
                conn.setRequestProperty(HEADER_SIGNATURE, "sha256=" + signature);
            }

            // Send payload
            byte[] payloadBytes = jsonPayload.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(payloadBytes.length));

            try (OutputStream os = conn.getOutputStream()) {
                os.write(payloadBytes);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            logger.debug("WebhookDispatcher: Response from " + webhook.getName() + ": " + responseCode);

            return responseCode;

        } finally {
            conn.disconnect();
        }
    }

    /**
     * Compute HMAC-SHA256 signature for the payload.
     */
    private String computeHmacSignature(String payload, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            logger.error("WebhookDispatcher: Failed to compute HMAC signature: " + e.getMessage());
            return "";
        }
    }

    /**
     * Convert bytes to hex string.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Generate unique delivery ID.
     */
    private synchronized String generateDeliveryId() {
        mDeliveryCounter++;
        return String.format("%d-%d", System.currentTimeMillis(), mDeliveryCounter);
    }

    /**
     * Shutdown the dispatcher gracefully.
     */
    public void shutdown() {
        if (mExecutor != null) {
            mExecutor.shutdown();
            try {
                if (!mExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                    mExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                mExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            logger.info("WebhookDispatcher: Shutdown complete");
        }
    }

    /**
     * Send a test webhook to verify configuration.
     */
    public boolean testWebhook(WebhookConfig webhook) {
        WebhookPayload payload = new WebhookPayload();
        payload.setEvent("test");
        payload.setTimestamp(new java.util.Date());

        try {
            int responseCode = deliver(webhook, payload, "test-" + System.currentTimeMillis(), 1);
            return responseCode >= 200 && responseCode < 300;
        } catch (Exception e) {
            logger.warn("WebhookDispatcher: Test webhook failed: " + e.getMessage());
            return false;
        }
    }
}

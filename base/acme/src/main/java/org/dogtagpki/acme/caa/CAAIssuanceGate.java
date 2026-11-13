// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Owns a long-lived validator and permits issuer submission after CAA approval.
 * Reuse one gate for requests sharing an issuer policy; close it at subsystem
 * shutdown. Configuration is supplied by the host, not by the request.
 */
public final class CAAIssuanceGate implements AutoCloseable {
    private final CAAValidator validator;
    private final AtomicBoolean closed = new AtomicBoolean();

    private CAAIssuanceGate(CAAValidator validator) {
        this.validator = validator;
    }

    /**
     * Disabled by default, including when upgrading an instance without caa.conf.
     */
    public static CAAIssuanceGate open(Properties properties, ClassLoader loader) throws DNSLookupException {
        Set<String> keys = Set.of("enabled", "issuerIdentifiers", "dns.class");
        for (String key : properties.stringPropertyNames()) {
            if (!keys.contains(key) && !key.startsWith("dns.settings.")) {
                throw DefaultCAAValidator.failure(DNSLookupException.Reason.CONFIGURATION, "Unknown CAA setting");
            }
        }

        String enabled = properties.getProperty("enabled", "false").strip();
        if (!Set.of("true", "false").contains(enabled)) {
            throw DefaultCAAValidator.failure(DNSLookupException.Reason.CONFIGURATION, "CAA enabled must be true or false");
        }

        if (enabled.equals("false")) {
            return new CAAIssuanceGate(null);
        }

        CAAPolicy policy;

        try {
            policy = new CAAPolicy(Arrays.stream(properties.getProperty("issuerIdentifiers", "").split(",", -1))
                    .map(String::strip).collect(Collectors.toSet()));
        } catch (IllegalArgumentException e) {
            throw DefaultCAAValidator.failure(DNSLookupException.Reason.CONFIGURATION, "Invalid CAA issuer identifiers");
        }

        var settings = new HashMap<String, String>();
        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith("dns.settings.")) {
                settings.put(key.substring(13), properties.getProperty(key));
            }
        }

        CAADNSClient client = CAADNSClientLoader.open(properties.getProperty("dns.class", ""), loader,
                new CAADNSClientProvider.Config(settings));
        return new CAAIssuanceGate(new DefaultCAAValidator(client, policy));
    }

    public boolean isEnabled() {
        return validator != null;
    }

    /**
     * Returns after an unexpired approval, or when CAA is disabled.
     *
     * - Observers run on the calling threads and may run concurrently.
     * - The observer receives evaluation evidence before the final gate check.
     *   The host records submission approval separately.
     * - Observer failure blocks submission.
     * - The host must preserve names, policy and freshness until signing.
     */
    public void check(CAARequest request, Consumer<CAADecision> observer) throws CAAApprovalException {
        if (closed.get()) {
            throw new IllegalStateException("CAA issuance gate is closed");
        }
        if (validator != null) {
            CAADecision decision = validator.validate(request);

            // Report evaluation even when expiry or shutdown subsequently
            // prevents submission. The host records the final gate outcome.
            observer.accept(decision);

            if (closed.get()) {
                throw new CAAApprovalException(decision, RejectionReason.CLOSED);
            }

            if (!Instant.now().isBefore(decision.expiresAt())) {
                throw new CAAApprovalException(decision, RejectionReason.EXPIRED);
            }

            if (decision.outcome() != CAADecision.Outcome.ALLOW) {
                throw new CAAApprovalException(decision, RejectionReason.EVALUATION);
            }
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true) && validator != null) validator.close();
    }

    /**
     * Separates evaluation failure from expiry or shutdown after evaluation.
     */
    public enum RejectionReason {
        // The validator returned DENY or ERROR; inspect its per-name reasons.
        EVALUATION,

        // The decision expired before submission, even if evaluation returned ALLOW.
        EXPIRED,

        // The gate closed after evaluation and blocked submission.
        CLOSED
    }

    /**
     * Typed refusal for the ACME host to persist and map to a problem document.
     */
    public static final class CAAApprovalException extends Exception {
        private static final long serialVersionUID = 1L;
        private final CAADecision decision;
        private final RejectionReason reason;

        CAAApprovalException(CAADecision decision, RejectionReason reason) {
            super("CAA authorization did not permit issuance");
            this.decision = decision;
            this.reason = reason;
        }

        public CAADecision decision() {
            return decision;
        }
        public RejectionReason reason() {
            return reason;
        }
    }
}

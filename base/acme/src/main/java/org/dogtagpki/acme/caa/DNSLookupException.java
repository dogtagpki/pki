// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.util.List;
import java.util.Objects;

/**
 * Transports a typed DNS lookup failure to the common CAA engine.
 */
public final class DNSLookupException extends Exception {
    private static final long serialVersionUID = 1L;
    private final Failure failure;

    public DNSLookupException(Failure failure) {
        super(failure.message());
        this.failure = failure;
    }

    public Failure failure() {
        return failure;
    }

    /**
     * Carries a bounded failure message and immutable partial response evidence.
     */
    public record Failure(
            Reason reason, String message,
            List<CAADNSClient.ResponseEvidence> partialResponses) {
        public Failure {
            Objects.requireNonNull(reason);
            Objects.requireNonNull(message);
            partialResponses = List.copyOf(partialResponses);
            if (message.length() > 1024 || message.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("Failure message must be bounded single-line text");
            }
        }
    }

    /**
     * Identifies a stable DNS adapter or lookup failure category.
     */
    public enum Reason {
        // Provider settings, class loading or initialization are unusable.
        CONFIGURATION,

        // A query timeout or the shared attempt deadline was reached.
        TIMEOUT,

        // The configured DNS endpoint could not be contacted or transport failed.
        UNREACHABLE,

        // The resolver returned a failure response code rather than data or absence.
        RCODE_FAILURE,

        // The response is invalid, inconsistent or unrelated to the query.
        MALFORMED_RESPONSE,

        // The response lacks the evidence needed to establish data or absence.
        INCOMPLETE_ANSWER,

        // Alias resolution revisited a name and cannot complete safely.
        ALIAS_LOOP,

        // Query, alias, concurrency or other bounded resource allowance was exhausted.
        LIMIT_EXCEEDED,

        // DNSSEC validation failed or required validation assurance was unavailable.
        VALIDATION_FAILURE,

        // The operation was interrupted or cancelled, including client shutdown.
        CANCELLED
    }
}

// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.util.List;
import java.util.Objects;

/**
 * Carries a typed DNS initialization or resolution failure across the adapter
 * boundary without exposing library-specific exceptions to the policy engine.
 *
 * Failure flow:
 * - Provider/loader initialization failures propagate to the host. An enabled
 *   configuration that cannot initialize must not silently disable CAA.
 * - During validation, the engine retains the Failure in a per-name ERROR
 *   decision. The gate blocks submission rather than treating failure as
 *   record absence or as a policy denial.
 * - Failure also represents deadline, resource-limit and cancellation errors.
 *
 * Reason supplies a stable category for handling and diagnostics. Message and
 * optional partial response evidence explain the failed operation; neither can
 * authorize issuance. Message bounds prevent oversized or multiline text, but
 * do not redact sensitive content. Callers should avoid logging raw resolver
 * diagnostics or response data by default.
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
     * Immutable failure detail retained when a DNS operation cannot complete.
     * reason identifies the failure category; message is limited to 1024 characters
     * and excludes control characters. partialResponses may be empty or retain
     * observations collected before failure. They are diagnostic evidence, not a
     * successful lookup, and must not be reused to authorize issuance.
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

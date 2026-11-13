// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Reports CAA evaluation for one issuance attempt.
 *
 * - Every name must allow for the aggregate outcome to be ALLOW.
 * - ERROR takes precedence over DENY. Per-name results retain
 *     both policy denials and evaluation failures.
 * - checkedAt is the evaluation completion time.
 * - expiresAt limits how long the decision can be used.
 * - ALLOW permits issuance within that lifetime, subject to the host's
 *     final admission checks and other certificate requirements.
 */
public record CAADecision(
        Outcome outcome,
        List<NameDecision> names,
        Instant checkedAt,
        Instant expiresAt) {
    public CAADecision {
        Objects.requireNonNull(outcome);
        names = List.copyOf(names);
        Objects.requireNonNull(checkedAt);
        Objects.requireNonNull(expiresAt);
        if (names.isEmpty()) {
            throw new IllegalArgumentException("Missing name decisions");
        }

        if (outcome != aggregateOutcome(names)) {
            throw new IllegalArgumentException("Contradictory aggregate outcome");
        }

        if (outcome == Outcome.ALLOW && !expiresAt.isAfter(checkedAt)) {
            throw new IllegalArgumentException("ALLOW decision must be usable at completion");
        }
    }

    /**
     * An incomplete evaluation takes precedence over a denial; all names must allow.
     */
    static Outcome aggregateOutcome(List<NameDecision> names) {
        Outcome aggregate = Outcome.ALLOW;
        for (NameDecision name : names) {
            if (name.outcome() == Outcome.ERROR) {
                return Outcome.ERROR;
            }

            if (name.outcome() == Outcome.DENY) {
                aggregate = Outcome.DENY;
            }
        }

        return aggregate;
    }

    /**
     * Reports one certificate name's outcome, explanation and DNS discovery.
     *
     * - outcome gives the broad result; reason explains it.
     * - relevantOwner identifies the selected CAA RRset owner when
     *     available. Parent or alias discovery can make it differ from the
     *     certificate name.
     * - discovery retains the DNS observations used for evaluation.
     * - For DNS_FAILURE, failure contains the detailed adapter
     *     or resource category, such as timeout or invalid DNSSEC assurance.
     *     Other reasons do not carry a DNS failure.
     */
    public record NameDecision(
            CAARequest.CertificateName name,
            Outcome outcome,
            Reason reason,
            Optional<DNSDomainName> relevantOwner,
            List<CAADNSClient.LookupResult> discovery,
            Optional<DNSLookupException.Failure> failure) {
        public NameDecision {
            Objects.requireNonNull(name);
            Objects.requireNonNull(outcome);
            Objects.requireNonNull(reason);
            Objects.requireNonNull(relevantOwner);
            discovery = List.copyOf(discovery);
            Objects.requireNonNull(failure);
            boolean expectsDnsFailure = reason == Reason.DNS_FAILURE;
            if (expectsDnsFailure != failure.isPresent()) {
                throw new IllegalArgumentException("DNS_FAILURE reason requires matching failure details");
            }

            // Enumerate every reason so a future reason requires an explicit
            // authorization decision instead of inheriting a default outcome.
            Outcome expected = switch (reason) {
                case NO_RESTRICTION, ISSUER_AUTHORIZED -> Outcome.ALLOW;
                case DNS_FAILURE, EXPIRED -> Outcome.ERROR;
                case ISSUER_NOT_AUTHORIZED, UNKNOWN_CRITICAL_PROPERTY,
                        UNSUPPORTED_PARAMETERS, MISSING_BINDING_CONTEXT -> Outcome.DENY;
            };
            if (outcome != expected) {
                throw new IllegalArgumentException("Contradictory outcome and reason");
            }

            if (outcome == Outcome.ALLOW && discovery.isEmpty()) {
                throw new IllegalArgumentException("ALLOW requires DNS discovery evidence");
            }
        }
    }

    /**
     * Broad result category; use the per-name reason for its explanation.
     */
    public enum Outcome {
        // All evaluated CAA restrictions permit this name or issuance attempt.
        ALLOW,

        // CAA policy does not authorize issuance; this is not a DNS outage.
        DENY,

        // Evaluation could not produce a usable approval; issuance must stop.
        ERROR
    }

    /**
     * Explains a name's outcome.
     *
     * - Multiple grants may fail differently. A denial reason summarizes
     *     evaluation rather than listing every rejected grant.
     * - A passing applicable grant produces ISSUER_AUTHORIZED, even
     *     when other records do not grant authorization.
     * - An unknown critical property blocks issuance regardless of grants.
     */
    public enum Reason {
        // Discovery found no applicable issuance restrictions, including iodef-only policy.
        NO_RESTRICTION,

        // At least one applicable grant matches the issuer and its binding requirements.
        ISSUER_AUTHORIZED,

        // No applicable grant matches the issuer and supplied binding facts.
        ISSUER_NOT_AUTHORIZED,

        // An unrecognized CAA property has its critical flag set.
        UNKNOWN_CRITICAL_PROPERTY,

        // No passing grant was found; a grant has unknown or duplicate parameters.
        UNSUPPORTED_PARAMETERS,

        // No passing grant was found; a grant needs unavailable account or method facts.
        MISSING_BINDING_CONTEXT,

        // Lookup, assurance, cancellation or resource failure; inspect failure.reason().
        DNS_FAILURE,

        // The decision's usable lifetime ended before evaluation completed.
        EXPIRED
    }
}

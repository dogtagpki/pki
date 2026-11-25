// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Reports the per-name results and aggregate outcome of one CAA issuance attempt.
 *
 * Outcomes
 * - ALLOW requires every name to allow issuance. The host applies its final
 *   admission checks and other certificate requirements before submission.
 * - ERROR takes precedence over DENY in the aggregate outcome.
 * - names retains each name's policy decision or evaluation failure, together
 *   with its DNS discovery evidence.
 *
 * Timing
 * - checkedAt records evaluation completion.
 * - startedAt and checkedAt are UTC audit timestamps.
 * - submissionDeadlineNanos is exclusive and local to this JVM and attempt.
 */
public record CAADecision(
        Outcome outcome,
        List<NameDecision> names,
        Instant startedAt,
        Instant checkedAt,
        long submissionDeadlineNanos) {
    public CAADecision {
        Objects.requireNonNull(outcome);
        names = List.copyOf(names);
        Objects.requireNonNull(checkedAt);
        Objects.requireNonNull(startedAt);
        if (names.isEmpty()) {
            throw new IllegalArgumentException("Missing name decisions");
        }

        if (outcome != aggregateOutcome(names)) {
            throw new IllegalArgumentException("Contradictory aggregate outcome");
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
     *   ISSUER_AUTHORIZED requires its last lookup to contain the selected
     *   RRset, with a terminal owner matching relevantOwner. NO_RESTRICTION
     *   requires complete absence discovery or an RRset without applicable properties.
     *   Approvals require trusted evidence for the full discovery sequence and
     *   reject unknown critical properties. Issuer and binding matching remain
     *   the producer's responsibility because they require policy and context.
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
                case DNS_FAILURE -> Outcome.ERROR;
                case ISSUER_NOT_AUTHORIZED, ACCOUNT_NOT_AUTHORIZED, VALIDATION_METHOD_NOT_AUTHORIZED,
                        UNKNOWN_CRITICAL_PROPERTY,
                        UNSUPPORTED_PARAMETERS, MISSING_BINDING_CONTEXT -> Outcome.DENY;
            };
            if (outcome != expected) {
                throw new IllegalArgumentException("Contradictory outcome and reason");
            }

            if (outcome == Outcome.ALLOW && discovery.isEmpty()) {
                throw new IllegalArgumentException("ALLOW requires DNS discovery evidence");
            }

            if (outcome == Outcome.ALLOW) {
                validateApproval(name, reason, relevantOwner, discovery);
            }
        }
    }

    /** Check public approval evidence independently of the producer's issuance policy. */
    private static void validateApproval(CAARequest.CertificateName name, Reason reason,
            Optional<DNSDomainName> owner, List<CAADNSClient.LookupResult> discovery) {
        DNSDomainName expected = name.baseName();
        for (int i = 0; i < discovery.size(); i++) {
            var lookup = discovery.get(i);
            if (expected.asciiAbsoluteName().equals(".") || !lookup.candidate().equals(expected)) {
                throw new IllegalArgumentException("Discovery must follow the certificate name's parent sequence");
            }
            if (lookup.responses().stream().anyMatch(response ->
                    response.validationStatus() == CAADNSClient.ValidationStatus.UNTRUSTED)) {
                throw new IllegalArgumentException("ALLOW requires trusted evidence for every lookup");
            }
            if (lookup.kind() == CAADNSClient.LookupKind.RRSET && i != discovery.size() - 1) {
                throw new IllegalArgumentException("Discovery must stop at the first RRset");
            }
            expected = expected.parent();
        }

        var selected = discovery.get(discovery.size() - 1);
        if (selected.kind() != CAADNSClient.LookupKind.RRSET) {
            if (reason != Reason.NO_RESTRICTION || !expected.asciiAbsoluteName().equals(".") || owner.isPresent()) {
                throw new IllegalArgumentException("Absence approval requires discovery through the TLD");
            }
            return;
        }
        if (owner.isEmpty() || !selected.terminalName().equals(owner.get())) {
            throw new IllegalArgumentException("Approval requires the selected RRset owner");
        }
        if (CAAPolicy.hasUnknownCriticalProperty(selected.records())) {
            throw new IllegalArgumentException("Unknown critical property prevents approval");
        }
        boolean hasApplicableRecords = !CAAPolicy.applicableRecords(selected.records(), name.wildcard()).isEmpty();
        if (hasApplicableRecords != (reason == Reason.ISSUER_AUTHORIZED)) {
            throw new IllegalArgumentException("Approval reason contradicts applicable issuance properties");
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

        // No passing grant was found; an accounturi restriction does not match.
        ACCOUNT_NOT_AUTHORIZED,

        // No passing grant was found; validationmethods excludes the method used.
        VALIDATION_METHOD_NOT_AUTHORIZED,

        // An unrecognized CAA property has its critical flag set.
        UNKNOWN_CRITICAL_PROPERTY,

        // No passing grant was found; a grant has unknown or duplicate parameters.
        UNSUPPORTED_PARAMETERS,

        // No passing grant was found; a grant needs unavailable account or method facts.
        MISSING_BINDING_CONTEXT,

        // Lookup, assurance, cancellation or resource failure; inspect failure.reason().
        DNS_FAILURE
    }
}

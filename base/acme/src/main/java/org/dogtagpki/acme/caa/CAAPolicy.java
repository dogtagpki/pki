// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Defines issuer identities, shared property rules, and fixed validator limits.
 *
 * Issuer selection:
 * - The host selects these identifiers for the CA that will actually issue.
 *   Enrollment input must not broaden this set.
 * - Multiple identifiers are alternative identities of that same authority,
 *   not a list of unrelated CAs. A grant matching any configured identifier
 *   can authorize issuance if its other restrictions also pass.
 * - The set must be nonempty and is copied to prevent later modification.
 * - Identifiers are ASCII DNS names without a final root dot. No whitespace
 *   trimming or IDNA conversion is performed here. Configured spelling is
 *   retained; the policy engine compares issuer identifiers ignoring case.
 *
 * Identifier examples:
 *
 * Value                         Result
 * "ca.example"                  accepted
 * "CA.Example"                  accepted; matches "ca.example" in CAA
 * "ca.example."                 rejected: final root dot
 * "https://ca.example"          rejected: URL rather than issuer identifier
 * "_ca.example"                 rejected: underscore
 * "*.example"                   rejected: wildcard
 * ""                            rejected: empty identifier
 *
 * Example policy:
 *   new CAAPolicy(Set.of("ca.example", "legacy-ca.example"))
 * Both identifiers must represent the intended issuing authority. This type
 * checks syntax; it cannot verify CPS declarations or which CA signs later.
 *
 * Fixed implementation choices:
 * - CAARequest bounds each attempt to 128 distinct certificate identities so
 *   rejected and timed-out attempts still have bounded per-name reporting work.
 * - Limits are deliberately not administrator settings in this initial design.
 * - One attempt shares its deadline, query allowance and alias allowance across
 *   all requested names, including parent discovery and alias traversal.
 * - Concurrency is bounded per validator instance, not across the deployment.
 *   When full, the validator rejects admission rather than queuing requests.
 * - New attempts require new DNS observations. The submission deadline
 *   is shared with DNS discovery and policy evaluation.
 * - DNSSEC behavior belongs to the selected DNS provider, not this policy.
 */
public record CAAPolicy(Set<String> issuerIdentifiers) {
    private static final Duration MAX_TIMEOUT = Duration.ofNanos(Long.MAX_VALUE);
    private static final Limits DEFAULT_LIMITS =
            new Limits(Duration.ofSeconds(5), Duration.ofSeconds(1), 128, 16, 8);

    public CAAPolicy {
        issuerIdentifiers = Set.copyOf(issuerIdentifiers);
        if (issuerIdentifiers.isEmpty()) {
            throw new IllegalArgumentException("Missing issuer identifiers");
        }

        for (String issuer : issuerIdentifiers) {
            validateIssuerIdentifier(issuer);
        }
    }

    /** Shared RFC 8659 critical-property rule for evaluation and approval evidence. */
    static boolean hasUnknownCriticalProperty(List<CAADNSClient.CAARecord> records) {
        // iodef is recognized even when report delivery is not implemented.
        Set<String> known = Set.of("issue", "issuewild", "iodef");
        return records.stream().anyMatch(record -> (record.flags() & 128) != 0
                && !known.contains(record.tag().toLowerCase(Locale.ROOT)));
    }

    /** Select the applicable issuance properties, including wildcard precedence. */
    static List<CAADNSClient.CAARecord> applicableRecords(List<CAADNSClient.CAARecord> records, boolean wildcard) {
        boolean wildcardPolicy = wildcard && records.stream().anyMatch(r -> r.tag().equalsIgnoreCase("issuewild"));
        String tag = wildcardPolicy ? "issuewild" : "issue";
        return records.stream().filter(record -> record.tag().equalsIgnoreCase(tag)).toList();
    }

    /**
     * Validates configured issuer syntax without treating the issuer as a certificate name.
     */
    static void validateIssuerIdentifier(String issuer) {
        // Configuration uses a domain without the terminating root dot. Parse
        // the absolute form for syntax checking; retain the configured spelling.
        String absoluteName = new DNSDomainName(issuer + ".").asciiAbsoluteName();
        if (absoluteName.equals(".") || absoluteName.contains("_")) {
            throw new IllegalArgumentException("Expected issuer DNS identifier");
        }
    }

    /**
     * Returns the fixed production limits. Constructing another Limits value
     * does not change this policy; tests can use such values for isolated budgets.
     *
     * Limit                         Default      Scope
     * totalTimeout                  5 seconds    entire validation attempt
     * queryTimeout                  1 second     each query, capped by time left
     * maxQueries                    128          entire validation attempt
     * maxAliases                    16           entire validation attempt
     * maxConcurrentChecks           8            one validator instance
     */
    public Limits limits() {
        return DEFAULT_LIMITS;
    }

    /**
     * Bounds the time, query count, alias count, and concurrency of CAA checks.
     *
     * - Durations and counts must be positive.
     * - Durations must fit signed long nanoseconds for deadline accounting.
     * - A query's effective timeout cannot exceed the attempt's remaining time,
     *   even if queryTimeout is larger than totalTimeout.
     * - These are resource bounds, not DNS TTLs or decision lifetimes.
     */
    public record Limits(
            Duration totalTimeout, Duration queryTimeout,
            int maxQueries, int maxAliases, int maxConcurrentChecks) {
        public Limits {
            validateTimeout(totalTimeout, "Total timeout");
            validateTimeout(queryTimeout, "Query timeout");
            if (maxQueries < 1 || maxAliases < 1 || maxConcurrentChecks < 1) {
                throw new IllegalArgumentException("CAA query, alias and concurrency limits must be positive");
            }
        }

        private static void validateTimeout(Duration timeout, String description) {
            Objects.requireNonNull(timeout, description);
            if (timeout.isZero() || timeout.isNegative()) {
                throw new IllegalArgumentException(description + " must be positive");
            }

            // Deadline accounting uses signed long nanoseconds. Check its range
            // explicitly rather than invoking toNanos() solely for its exception.
            if (timeout.compareTo(MAX_TIMEOUT) > 0) {
                throw new IllegalArgumentException(description + " exceeds the nanosecond deadline range");
            }
        }
    }
}

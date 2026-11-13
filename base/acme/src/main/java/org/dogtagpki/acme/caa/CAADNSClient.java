// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Resolves CAA through aliases without performing parent discovery.
 * A subsystem-owned client supports concurrent calls with separate attempt
 * budgets; provider configuration remains fixed for the client's lifetime.
 */
public interface CAADNSClient extends AutoCloseable {
    /**
     * Read-only validation behavior fixed by the selected provider.
     */
    ValidationMode validationMode();

    /**
     * Returns a complete relevant RRset or established absence, or throws a
     * typed failure. An empty record list alone does not establish absence;
     * incomplete or failed lookups must not be reported as absence.
     * Charge queries and aliases to the caller's attempt budget and
     * honor its deadline. The budget is not retained after this call.
     */
    LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget)
            throws DNSLookupException;

    /**
     * Rejects new lookups and cancels waiting callers. Must be idempotent and
     * safe alongside active calls. Library-owned transport operations may
     * finish separately under their query timeouts; they must remain bounded.
     * The host does not wait for transport cleanup before returning from close().
     */
    void close();

    /**
     * Returns terminal CAA data or absence with supporting DNS observations.
     *
     * - candidate: the original lookup name.
     * - terminalName: the name reached after alias resolution.
     * - aliases: ordered from candidate to terminalName.
     * - responses: ordered by resolution, with the terminal response last.
     */
    public record LookupResult(
            DNSDomainName candidate,
            DNSDomainName terminalName,
            LookupKind kind,
            List<CAARecord> records,
            List<AliasStep> aliases,
            List<ResponseEvidence> responses,
            Optional<SOAEvidence> negativeSoa) {
        private static final int RCODE_NOERROR = 0;
        private static final int RCODE_NXDOMAIN = 3;

        public LookupResult {
            Objects.requireNonNull(candidate);
            Objects.requireNonNull(terminalName);
            Objects.requireNonNull(kind);
            records = List.copyOf(records);
            aliases = List.copyOf(aliases);
            responses = List.copyOf(responses);
            Objects.requireNonNull(negativeSoa);
            if (responses.isEmpty()) {
                throw new IllegalArgumentException("Missing DNS response evidence");
            }

            if (responses.stream().anyMatch(response -> response.rcode() != RCODE_NOERROR
                    && response.rcode() != RCODE_NXDOMAIN)) {
                throw new IllegalArgumentException("Failed DNS response cannot be a successful lookup");
            }

            int terminalRcode = responses.get(responses.size() - 1).rcode();
            int expectedTerminalRcode = kind == LookupKind.NXDOMAIN ? RCODE_NXDOMAIN : RCODE_NOERROR;
            if (terminalRcode != expectedTerminalRcode) {
                throw new IllegalArgumentException("Lookup kind contradicts response RCODE");
            }

            if (kind == LookupKind.RRSET) {
                if (responses.stream().anyMatch(response -> response.rcode() != RCODE_NOERROR)) {
                    throw new IllegalArgumentException("Positive lookup cannot contain an NXDOMAIN response");
                }

                if (records.isEmpty() || negativeSoa.isPresent()) {
                    throw new IllegalArgumentException("Positive lookup requires records and no negative evidence");
                }

                if (records.stream().anyMatch(r -> !r.owner().equals(terminalName))) {
                    throw new IllegalArgumentException("CAA owner differs from terminal name");
                }
            } else if (!records.isEmpty()) {
                throw new IllegalArgumentException("Negative lookup cannot contain CAA records");
            }

            DNSDomainName next = candidate;
            Set<DNSDomainName> visited = new HashSet<>();
            visited.add(candidate);
            for (AliasStep alias : aliases) {
                if (!next.equals(alias.source()) || !visited.add(alias.target())) {
                    throw new IllegalArgumentException("Disconnected or looping alias chain");
                }

                next = alias.target();
            }

            if (!next.equals(terminalName)) {
                throw new IllegalArgumentException("Alias chain does not reach terminal name");
            }
        }
    }

    /**
     * Distinguishes a positive RRset from terminal record or name absence.
     */
    public enum LookupKind {
        // A complete relevant CAA record set was found.
        RRSET,

        // Resolution established that the terminal name has no CAA records.
        NODATA,

        // Resolution established that the terminal DNS name does not exist.
        NXDOMAIN
    }

    /**
     * Preserves a CAA resource record's owner, TTL, flags, tag, and value.
     */
    public record CAARecord(
            DNSDomainName owner, long ttlSeconds, int flags,
            String tag, byte[] value) {
        public CAARecord {
            Objects.requireNonNull(owner);
            Objects.requireNonNull(tag);
            value = value.clone();
            // TTL is a nonnegative 31-bit value. RDATA permits 65535 octets:
            // one flags octet, one tag-length octet, then the tag and value.
            if (ttlSeconds < 0 || ttlSeconds > 0x7fffffffL || flags < 0 || flags > 255
                    || !tag.matches("[A-Za-z0-9]{1,255}") || tag.length() + value.length > 65533) {
                throw new IllegalArgumentException("Invalid CAA record fields");
            }
        }

        @Override
        public byte[] value() {
            return value.clone();
        }
    }

    /**
     * Records one connected alias transition used during resolution.
     */
    public record AliasStep(
            DNSDomainName source, DNSDomainName target,
            AliasKind kind, long ttlSeconds) {
        public AliasStep {
            Objects.requireNonNull(source);
            Objects.requireNonNull(target);
            Objects.requireNonNull(kind);
            if (source.equals(target) || ttlSeconds < 0 || ttlSeconds > 0x7fffffffL) {
                throw new IllegalArgumentException("Invalid alias step");
            }
        }
    }

    /**
     * Identifies an alias mechanism when its provenance is known.
     */
    public enum AliasKind {
        // A CNAME redirects the current name to its target.
        CNAME,

        // A DNAME redirects a suffix, producing a target for the current name.
        DNAME_SYNTHESIS
    }

    /**
     * Records resolver, transport, timing, and validation observations.
     *
     * - authenticatedData: the observed AD flag.
     * - validationStatus: the classification established by the provider.
     * - assurance: why that classification can be relied on.
     * - AD alone establishes no trust. An unchecked provider may observe it
     *   without asserting DNSSEC assurance.
     * - Extended errors are diagnostics, not proof of security or insecurity.
     *   Avoid logging raw diagnostic text by default.
     */
    public record ResponseEvidence(
            String resolverId,
            DNSDomainName question, int rcode, boolean authenticatedData,
            DNSSECStatus validationStatus, ValidationAssurance assurance,
            Instant receivedAt, String transport,
            Optional<ExtendedError> diagnostic) {
        public ResponseEvidence {
            Objects.requireNonNull(resolverId);
            Objects.requireNonNull(question);
            Objects.requireNonNull(validationStatus);
            Objects.requireNonNull(assurance);
            Objects.requireNonNull(receivedAt);
            Objects.requireNonNull(transport);
            Objects.requireNonNull(diagnostic);
            if (rcode < 0 || rcode > 4095 || resolverId.isBlank()) {
                throw new IllegalArgumentException("Invalid DNS response identity or RCODE");
            }

            boolean classificationMatchesAssurance = switch (assurance) {
                case NONE -> validationStatus == DNSSECStatus.UNCHECKED;
                case TRUSTED_RESOLVER -> validationStatus == DNSSECStatus.UNCLASSIFIED
                        || (validationStatus == DNSSECStatus.SECURE && authenticatedData);
            };
            if (!classificationMatchesAssurance) {
                throw new IllegalArgumentException("Contradictory validation status and assurance");
            }
        }
    }

    /**
     * Retains SOA fields needed to determine negative-cache lifetime.
     */
    public record SOAEvidence(
            DNSDomainName owner, long ttlSeconds, long minimumSeconds) {
        public SOAEvidence {
            Objects.requireNonNull(owner);
            if (ttlSeconds < 0 || ttlSeconds > 0x7fffffffL || minimumSeconds < 0 || minimumSeconds > 0xffffffffL) {
                throw new IllegalArgumentException("Invalid SOA TTL or MINIMUM");
            }
        }
    }

    /**
     * Carries an optional DNS extended-error code and diagnostic text.
     */
    public record ExtendedError(int code, Optional<String> text) {
        public ExtendedError {
            Objects.requireNonNull(text);
            if (code < 0 || code > 65535 || text.map(String::length).orElse(0) > 1024) {
                throw new IllegalArgumentException("Invalid or oversized extended error");
            }
        }
    }

    /**
     * Describes fixed provider behavior; this is not a configuration parameter.
     */
    public enum ValidationMode {
        // DNS responses carry no required DNSSEC assurance.
        UNCHECKED,

        // A trusted resolver enforces DNSSEC and withholds bogus answers.
        DELEGATED_ENFORCING
    }

    /**
     * Classifies the DNSSEC status established for an observed response.
     * UNCLASSIFIED with TRUSTED_RESOLVER is accepted under the enforcing-resolver
     * contract: the resolver withholds bogus answers. It does not independently
     * prove that the domain is insecure or unsigned.
     */
    public enum DNSSECStatus {
        // The trusted validating resolver reports authenticated data.
        SECURE,

        // Accepted through trusted delegation without a secure classification.
        UNCLASSIFIED,

        // No DNSSEC classification is established by this provider.
        UNCHECKED
    }

    /**
     * Identifies the trusted source of a validation classification.
     */
    public enum ValidationAssurance {
        // No trusted DNSSEC enforcement is asserted for this response.
        NONE,

        // Acceptance relies on the configured enforcing resolver and trusted channel.
        TRUSTED_RESOLVER
    }

    /**
     * Shares one deadline and query/alias allowance across a CAA attempt.
     */
    public interface LookupBudget {
        /**
         * Returns time left on the monotonic attempt deadline, clamped at zero.
         */
        Duration remaining();
        /**
         * Returns the per-query cap; a client must also respect remaining().
         */
        Duration queryTimeout();
        /**
         * Reserves allowance before issuing each DNS query, including retries.
         */
        void reserveQuery() throws DNSLookupException;
        /**
         * Reserves allowance before following each alias transition.
         */
        void reserveAlias() throws DNSLookupException;
    }
}

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
 * DNS adapter boundary used by the shared CAA policy engine. Implementations
 * translate library-specific DNS messages into this interface's result model,
 * keeping DNS library types out of the validator and consuming subsystem.
 * Every implementation must use trusted DNSSEC validation. Delegated
 * implementations must use a protected channel to a trusted enforcing
 * resolver that withholds bogus answers.
 *
 * Resolution scope:
 * - One resolveCaa() call starts at one candidate and follows CNAME/DNAME aliases
 *   to a terminal RRset or established absence. It may require multiple queries.
 * - The client does not search parents. On absence, DefaultCAAValidator selects
 *   the original candidate's parent and makes another call with the same budget.
 * - The adapter establishes response relevance and completeness, enforces its
 *   DNSSEC enforcement contract, and reports failures through DNSLookupException.
 *   Empty or incomplete data must not be substituted for established absence.
 *
 * A client is opened once for a configured provider and owned through the
 * validator's lifecycle. It supports concurrent calls with separate attempt
 * budgets. Resolver configuration remains fixed until the client is replaced.
 * Each call charges queries and alias transitions to its supplied budget and
 * must honor deadlines and cancellation in the underlying transport.
 */
public interface CAADNSClient extends AutoCloseable {
    /**
     * Returns a complete relevant RRset or established absence, or throws a
     * typed failure. An empty record list alone does not establish absence;
     * incomplete or failed lookups must not be reported as absence.
     * Every response used for a successful result must carry SECURE or
     * UNCLASSIFIED status from a trusted enforcing resolver. The validator rejects
     * UNTRUSTED observations before policy evaluation.
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
     * Carries the result of one candidate lookup, including any alias traversal.
     * This is DNS evidence for policy evaluation, not an issuance decision.
     *
     * Fields:
     * - candidate is the original name supplied to resolveCaa().
     * - terminalName is the name reached after following the ordered aliases.
     * - kind distinguishes a CAA RRset from record absence or name absence.
     * - records contains the terminal CAA RRset; negative results have no records.
     * - responses contains observations in resolution order, terminal response last.
     * - negativeSoa optionally supplies negative-answer metadata.
     *
     * Example: www.customer.example. is a CNAME for edge.hosting.example.
     * - candidate:     www.customer.example.
     * - terminalName:  edge.hosting.example.
     * - aliases:       one CNAME transition connecting those names
     * - responses:     one or more responses used to resolve that transition
     * If the target has no CAA, return absence here. The validator next searches
     * customer.example., not hosting.example.
     *
     * Constructor checks reject inconsistent fields and disconnected alias chains.
     * They do not establish completeness or DNS authenticity; the adapter must
     * establish those properties under its configured validation contract.
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
     * - validationStatus: SECURE or UNCLASSIFIED means acceptance relies on a
     *   trusted enforcing resolver; AD alone does not establish that trust.
     * - UNTRUSTED retains observations without established assurance for failure
     *   diagnostics. The validator rejects them as successful discovery evidence.
     * - Extended errors are diagnostics, not proof of security or insecurity.
     *   Avoid logging raw diagnostic text by default.
     */
    public record ResponseEvidence(
            String resolverId,
            DNSDomainName question, int rcode, boolean authenticatedData,
            ValidationStatus validationStatus,
            Instant receivedAt, String transport,
            Optional<ExtendedError> diagnostic) {
        public ResponseEvidence {
            Objects.requireNonNull(resolverId);
            Objects.requireNonNull(question);
            Objects.requireNonNull(validationStatus);
            Objects.requireNonNull(receivedAt);
            Objects.requireNonNull(transport);
            Objects.requireNonNull(diagnostic);
            if (rcode < 0 || rcode > 4095 || resolverId.isBlank()) {
                throw new IllegalArgumentException("Invalid DNS response identity or RCODE");
            }

            if (validationStatus == ValidationStatus.SECURE && !authenticatedData) {
                throw new IllegalArgumentException("Secure resolver status requires authenticated data");
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
     * Describes whether an observed response has trusted DNSSEC enforcement.
     * SECURE and UNCLASSIFIED both rely on a trusted enforcing resolver and
     * protected channel. UNCLASSIFIED does not independently prove that the
     * domain is insecure or unsigned. UNTRUSTED cannot authorize issuance.
     */
    public enum ValidationStatus {
        // The trusted enforcing resolver reports authenticated data (AD set).
        SECURE,

        // The trusted enforcing resolver accepted the answer without AD.
        UNCLASSIFIED,

        // Required DNSSEC assurance was not established; reject this evidence.
        UNTRUSTED
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

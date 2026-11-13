// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

import org.dogtagpki.acme.caa.CAADNSClient.LookupResult;
import org.dogtagpki.acme.caa.CAADecision.NameDecision;
import org.dogtagpki.acme.caa.CAADecision.Outcome;
import org.dogtagpki.acme.caa.CAADecision.Reason;

/**
 * Shared CAA discovery and policy, independent of DNS toolkit and enrollment protocol.
 */
public final class DefaultCAAValidator implements CAAValidator {
    private final CAADNSClient client;
    private final CAAPolicy policy;
    private final Semaphore checks;
    private final AtomicBoolean closed = new AtomicBoolean();

    public DefaultCAAValidator(CAADNSClient client, CAAPolicy policy) {
        this.client = java.util.Objects.requireNonNull(client);
        this.policy = java.util.Objects.requireNonNull(policy);
        checks = new Semaphore(policy.limits().maxConcurrentChecks());
    }

    /**
     * Discovers policy for each name, then combines the per-name decisions.
     * DNS observations are reused only within this attempt; wildcard and binding
     * rules are evaluated separately for each certificate name. Continue after
     * a name fails so the result describes every requested name.
     *
     * Certificate name
     *       |
     *       v
     * Resolve candidate, following aliases
     *       |
     *       +-- DNS failure ----------> ERROR
     *       |
     *       +-- CAA RRset ------------> Evaluate policy
     *       |
     *       +-- Established absence
     *                 |
     *                 v
     *        Original candidate's parent
     *                 |
     *                 +-- Not root --> Repeat lookup
     *                 |
     *                 +-- Root ------> No restriction
     */
    @Override
    public CAADecision validate(CAARequest request) {
        Instant started = Instant.now();
        // One resource budget covers the entire attempt, including all names,
        // parent lookups and alias traversal. Starting another name does not reset it.
        Budget budget = new Budget(policy.limits());
        List<NameDecision> decisions = new ArrayList<>();
        Map<DNSDomainName, LookupResult> observations = new HashMap<>();

        boolean admitted = !closed.get() && checks.tryAcquire();
        try {
            for (CAARequest.CertificateName name : request.names()) {
                List<LookupResult> discovery = new ArrayList<>();

                try {
                    if (!admitted || closed.get()) {
                        throw failure(closed.get() ? DNSLookupException.Reason.CANCELLED
                                : DNSLookupException.Reason.LIMIT_EXCEEDED, "CAA checker unavailable");
                    }

                    DNSDomainName candidate = name.baseName();
                    Reason reason = Reason.NO_RESTRICTION;
                    Optional<DNSDomainName> owner = Optional.empty();

                    while (!candidate.asciiAbsoluteName().equals(".")) {
                        // Stop on interruption or the total lookup deadline, even
                        // when this candidate reuses an observation from this attempt.
                        // The DNS client charges actual queries and alias transitions.
                        budget.check();
                        LookupResult result = observations.get(candidate);
                        if (result == null) {
                            result = client.resolveCaa(candidate, budget);
                            verifyAssurance(candidate, result);
                            observations.put(candidate, result);
                        }

                        discovery.add(result);

                        if (result.kind() == CAADNSClient.LookupKind.RRSET) {
                            owner = Optional.of(result.terminalName());
                            reason = evaluate(result.records(), name, request.contexts().get(name));
                            break;
                        }

                        // RFC 8659 Section 3: climb the original candidate, never an alias target.
                        String original = candidate.asciiAbsoluteName();
                        String parent = original.substring(original.indexOf('.') + 1);
                        candidate = new DNSDomainName(parent.isEmpty() ? "." : parent);
                    }

                    // A lookup or policy evaluation may have used the remaining
                    // time. Check again before accepting this name's outcome.
                    budget.check();
                    Outcome outcome = reason == Reason.NO_RESTRICTION || reason == Reason.ISSUER_AUTHORIZED
                            ? Outcome.ALLOW : Outcome.DENY;
                    decisions.add(new NameDecision(name, outcome, reason, owner, discovery, Optional.empty()));
                } catch (DNSLookupException e) {
                    decisions.add(new NameDecision(name, Outcome.ERROR, Reason.DNS_FAILURE,
                            Optional.empty(), discovery, Optional.of(e.failure())));
                }
            }
        } finally {
            if (admitted) checks.release();
        }

        Instant finished = Instant.now();
        Outcome outcome = CAADecision.aggregateOutcome(decisions);

        // No cross-request cache or reusable authorization token. Cap age from
        // the oldest response, including parent/alias observations, at eight hours.
        Instant oldest = observations.values().stream().flatMap(r -> r.responses().stream())
                .map(CAADNSClient.ResponseEvidence::receivedAt).min(Instant::compareTo).orElse(started);
        Instant expires = oldest.plus(policy.maxDecisionAge());

        if (closed.get()) {
            var cancelled = failure(DNSLookupException.Reason.CANCELLED, "CAA checker closed").failure();
            decisions = decisions.stream().map(d -> new NameDecision(d.name(), Outcome.ERROR, Reason.DNS_FAILURE,
                    d.relevantOwner(), d.discovery(), Optional.of(cancelled))).toList();
            outcome = Outcome.ERROR;
        } else if (!expires.isAfter(finished)) {
            decisions = request.names().stream().map(name -> new NameDecision(name, Outcome.ERROR, Reason.EXPIRED,
                    Optional.empty(), List.of(), Optional.<DNSLookupException.Failure>empty())).toList();
            outcome = Outcome.ERROR;
        }

        return new CAADecision(outcome, decisions, finished, expires);
    }

    /**
     * Rejects a provider that returns assurance contradicting its fixed contract.
     */
    private void verifyAssurance(DNSDomainName candidate, LookupResult result) throws DNSLookupException {
        if (!candidate.equals(result.candidate())) {
            throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "CAA candidate mismatch");
        }

        for (var response : result.responses()) {
            boolean valid = switch (client.validationMode()) {
                case UNCHECKED -> response.assurance() == CAADNSClient.ValidationAssurance.NONE;
                case DELEGATED_ENFORCING -> response.assurance() == CAADNSClient.ValidationAssurance.TRUSTED_RESOLVER;
            };
            if (!valid) {
                throw failure(DNSLookupException.Reason.VALIDATION_FAILURE, "Missing required DNS assurance");
            }
        }
    }

    /**
     * Evaluates the first discovered RRset. For wildcards, any issuewild record
     * takes precedence over all issue records. An RRset containing only iodef
     * or other non-applicable properties stops discovery without restricting
     * issuance. Applicable grants are additive: one passing grant is sufficient.
     *
     * Unrecognized property with critical flag set? -- yes --> DENY
     *           |
     *           no
     *           v
     * Wildcard and issuewild present?
     *           |
     *           +-- yes --> Evaluate issuewild records
     *           |
     *           +-- no ---> Evaluate issue records
     *                               |
     *                               +-- None applicable --> No restriction
     *                               |
     *                               +-- Any grant passes -> Authorized
     *                               |
     *                               +-- No grant passes --> DENY
     */
    private Reason evaluate(List<CAADNSClient.CAARecord> records, CAARequest.CertificateName name,
            CAARequest.IssuanceContext context) {
        Set<String> known = Set.of("issue", "issuewild", "iodef");

        // RFC 8659 Section 4.5: an unrecognized critical property blocks issuance.
        for (var record : records) {
            if ((record.flags() & 128) != 0 && !known.contains(record.tag().toLowerCase(Locale.ROOT))) {
                return Reason.UNKNOWN_CRITICAL_PROPERTY;
            }
        }

        // RFC 8659 Section 4.3: issuewild overrides issue for wildcard names.
        boolean wildcardPolicy = name.wildcard()
                && records.stream().anyMatch(r -> r.tag().equalsIgnoreCase("issuewild"));
        String tag = wildcardPolicy ? "issuewild" : "issue";
        List<CAADNSClient.CAARecord> applicable = records.stream()
                .filter(r -> r.tag().equalsIgnoreCase(tag)).toList();

        if (applicable.isEmpty()) {
            return Reason.NO_RESTRICTION;
        }

        // RFC 8659 Section 4.2: applicable records grant independently.
        Reason denied = Reason.ISSUER_NOT_AUTHORIZED;
        for (var record : applicable) {
            Reason result = grant(record.value(), context);
            if (result == Reason.ISSUER_AUTHORIZED) {
                return result;
            }
            if (result != Reason.ISSUER_NOT_AUTHORIZED) {
                denied = result;
            }
        }

        return denied;
    }

    /**
     * A malformed or unsatisfied property grants nothing; another property may
     * grant. Unknown or duplicate parameters conservatively reject this grant
     * rather than ignoring a possible restriction or choosing an ambiguous value.
     * Issuer matching ignores case; account URI matching preserves the exact
     * string supplied in the trusted issuance context.
     */
    private Reason grant(byte[] bytes, CAARequest.IssuanceContext context) {
        for (byte b : bytes) {
            int value = Byte.toUnsignedInt(b);
            if (value > 126 || (value < 32 && value != 9)) {
                return Reason.ISSUER_NOT_AUTHORIZED;
            }
        }

        String[] parts = new String(bytes, StandardCharsets.US_ASCII).split(";", -1);
        String issuer = parts[0].strip();
        try {
            CAAPolicy.validateIssuerIdentifier(issuer);
        } catch (IllegalArgumentException e) {
            return Reason.ISSUER_NOT_AUTHORIZED;
        }

        if (policy.issuerIdentifiers().stream().noneMatch(issuer::equalsIgnoreCase)) {
            return Reason.ISSUER_NOT_AUTHORIZED;
        }

        Map<String, String> parameters = new HashMap<>();
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i].strip();
            if (part.isEmpty() && parts.length == 2) continue;

            int separator = part.indexOf('=');
            if (separator < 0) {
                return Reason.ISSUER_NOT_AUTHORIZED;
            }

            String key = part.substring(0, separator).stripTrailing();
            String value = part.substring(separator + 1).stripLeading();
            if (!validParameterTag(key)) {
                return Reason.ISSUER_NOT_AUTHORIZED;
            }

            for (int j = 0; j < value.length(); j++) {
                if (value.charAt(j) < 0x21 || value.charAt(j) > 0x7e) {
                    return Reason.ISSUER_NOT_AUTHORIZED;
                }
            }

            if (parameters.putIfAbsent(key, value) != null) {
                return Reason.UNSUPPORTED_PARAMETERS;
            }
        }

        for (var parameter : parameters.entrySet()) {
            if (!Set.of("accounturi", "validationmethods").contains(parameter.getKey())) {
                return Reason.UNSUPPORTED_PARAMETERS;
            }
            if (context == null) {
                return Reason.MISSING_BINDING_CONTEXT;
            }
            if (parameter.getKey().equals("accounturi")) {
                // RFC 8657 Section 3 requires the URI to identify the requesting account.
                // This implementation uses exact string comparison without normalization.
                if (context.accountUri().isEmpty()) {
                    return Reason.MISSING_BINDING_CONTEXT;
                }
                if (!context.accountUri().get().toString().equals(parameter.getValue())) {
                    return Reason.ISSUER_NOT_AUTHORIZED;
                }
            } else {
                if (context.validationMethod().isEmpty()) {
                    return Reason.MISSING_BINDING_CONTEXT;
                }
                // RFC 8657 Section 4: require the method used for this name.
                String methods = parameter.getValue();
                if (!matchesValidationMethod(methods, context.validationMethod().get())) {
                    return Reason.ISSUER_NOT_AUTHORIZED;
                }
            }
        }

        return Reason.ISSUER_AUTHORIZED;
    }

    /**
     * Parses attacker-controlled parameter tags without recursive regular expressions.
     */
    private static boolean validParameterTag(String tag) {
        if (tag.isEmpty() || !isAlphaNumeric(tag.charAt(0))
                || !isAlphaNumeric(tag.charAt(tag.length() - 1))) {
            return false;
        }

        for (int i = 1; i < tag.length() - 1; i++) {
            char c = tag.charAt(i);
            if (!isAlphaNumeric(c) && c != '-') {
                return false;
            }
        }

        return true;
    }

    /**
     * Validates every label, including labels after a matching method.
     */
    private static boolean matchesValidationMethod(String methods, String method) {
        boolean matched = false;
        for (String label : methods.split(",", -1)) {
            if (label.isEmpty()) {
                return false;
            }

            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!isAlphaNumeric(c) && c != '-') {
                    return false;
                }
            }

            matched |= label.equals(method);
        }

        return matched;
    }

    private static boolean isAlphaNumeric(char c) {
        return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9';
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            client.close();
        }
    }

    static DNSLookupException failure(DNSLookupException.Reason reason, String message) {
        return new DNSLookupException(new DNSLookupException.Failure(reason, message, List.of()));
    }

    /**
     * One monotonic deadline and query/alias allowance shared by all names in
     * an attempt. These limits bound lookup work; they are separate from the
     * completed CAA decision's expiry and from DNS record TTLs.
     */
    static final class Budget implements CAADNSClient.LookupBudget {
        private final long started = System.nanoTime();
        private final CAAPolicy.Limits limits;
        private int queries;
        private int aliases;

        Budget(CAAPolicy.Limits limits) {
            this.limits = limits;
        }

        @Override
        public Duration remaining() {
            long elapsed = System.nanoTime() - started;
            return elapsed >= limits.totalTimeout().toNanos() ? Duration.ZERO
                    : Duration.ofNanos(limits.totalTimeout().toNanos() - elapsed);
        }

        @Override
        public Duration queryTimeout() {
            return limits.queryTimeout();
        }

        @Override
        public void reserveQuery() throws DNSLookupException {
            check();
            if (++queries > limits.maxQueries()) {
                throw failure(DNSLookupException.Reason.LIMIT_EXCEEDED,
                        "CAA query limit exceeded");
            }
        }

        @Override
        public void reserveAlias() throws DNSLookupException {
            check();
            if (++aliases > limits.maxAliases()) {
                throw failure(DNSLookupException.Reason.LIMIT_EXCEEDED,
                        "CAA alias limit exceeded");
            }
        }

        /**
         * Checks cancellation and elapsed time without consuming an allowance.
         * reserveQuery() and reserveAlias() additionally charge their counters
         * before the DNS client performs the corresponding work.
         */
        void check() throws DNSLookupException {
            if (Thread.currentThread().isInterrupted()) {
                throw failure(DNSLookupException.Reason.CANCELLED, "CAA check interrupted");
            }
            if (remaining().isZero()) {
                throw failure(DNSLookupException.Reason.TIMEOUT, "CAA deadline exceeded");
            }
        }
    }
}

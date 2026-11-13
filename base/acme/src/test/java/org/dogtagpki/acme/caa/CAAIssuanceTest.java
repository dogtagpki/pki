// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later
package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

/** Exercises the real discovery engine and issuer gate without external DNS. */
class CAAIssuanceTest {
    private static final String ISSUER = "ca.example";
    private static final CAARequest.CertificateName NAME = name("www.customer.test", false);

    @Test void climbsOriginalParentsIncludingTldAndExcludesRoot() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(NAME)).outcome());
            assertEquals(List.of("www.customer.test.", "customer.test.", "test."), client.queries);
        }
    }

    @Test void aliasAbsenceClimbsOriginalParentRatherThanAliasParent() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            var candidate = NAME.baseName();
            var target = domain("edge.hosting.test");
            client.answers.put(candidate, new CAADNSClient.LookupResult(candidate, target, CAADNSClient.LookupKind.NODATA,
                    List.of(), List.of(new CAADNSClient.AliasStep(candidate, target, CAADNSClient.AliasKind.CNAME, 60)),
                    List.of(evidence(candidate)), Optional.empty()));
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER));
            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(NAME)).outcome());
            assertEquals(List.of("www.customer.test.", "customer.test."), client.queries);
        }
    }

    @Test void iodefOnlyStopsSearchWithoutRestrictingIssuers() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "iodef", "mailto:security@example.com"));
            client.put("customer.test", record("customer.test", 0, "issue", ";"));
            assertEquals(CAADecision.Reason.NO_RESTRICTION, validator.validate(request(NAME)).names().get(0).reason());
            assertEquals(1, client.queries.size());
        }
    }

    @Test void emptyAndMalformedIssueDoNotOverrideAnotherGrant() throws Exception {
        for (String value : List.of(";", "", "%%%%%", ISSUER + "; malformed")) {
            try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
                client.put("www.customer.test", record("www.customer.test", 0, "issue", value),
                        record("www.customer.test", 0, "issue", ISSUER.toUpperCase()));
                assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(NAME)).outcome());
            }
        }
    }

    @Test void malformedIssueAloneDoesNotGrant() throws Exception {
        for (String value : List.of(";", "%%%%%", ISSUER + "; malformed", ISSUER + ";x=a b")) {
            try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
                client.put("www.customer.test", record("www.customer.test", 0, "issue", value));
                assertEquals(CAADecision.Outcome.DENY, validator.validate(request(NAME)).outcome());
            }
        }
    }

    @Test void wildcardPrecedenceAndSameAttemptLookupSharing() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER),
                    record("www.customer.test", 0, "issuewild", ";"));
            var result = validator.validate(request(NAME, name("www.customer.test", true)));
            assertEquals(CAADecision.Outcome.ALLOW, result.names().get(0).outcome());
            assertEquals(CAADecision.Outcome.DENY, result.names().get(1).outcome());
            assertEquals(1, client.queries.size());
        }
    }

    @Test void criticalMaskIs128AndReservedBitsAreIgnored() throws Exception {
        for (int flags : List.of(1, 128)) {
            try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
                client.put("www.customer.test", record("www.customer.test", flags, "future", "opaque"));
                assertEquals(flags == 128 ? CAADecision.Outcome.DENY : CAADecision.Outcome.ALLOW,
                        validator.validate(request(NAME)).outcome());
            }
        }
    }

    @Test void bindingRequiresExactAccountAndSuccessfulMethodContext() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue",
                    ISSUER + "; accounturi=https://acme.example/acct/1; validationmethods=dns-01,http-01"));
            assertEquals(CAADecision.Outcome.DENY, validator.validate(request(NAME)).outcome());
            for (String account : List.of("https://acme.example/acct/1", "https://ACME.example/acct/1")) {
                var context = new CAARequest.IssuanceContext(Optional.of(URI.create(account)), Optional.of("dns-01"));
                var request = new CAARequest(List.of(NAME), Map.of(NAME, context));
                assertEquals(account.contains("ACME") ? CAADecision.Outcome.DENY : CAADecision.Outcome.ALLOW,
                        validator.validate(request).outcome());
            }
        }
    }

    @Test void unsupportedAndDuplicateParametersGrantNothing() throws Exception {
        for (String parameters : List.of("x=y", "accounturi=x;accounturi=x", "validationmethods=")) {
            try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
                client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER + ";" + parameters));
                assertEquals(CAADecision.Outcome.DENY, validator.validate(request(NAME)).outcome());
            }
        }
    }

    @Test void lookupErrorsStopDiscoveryAndNeverBecomeAbsence() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.error = true;
            var result = validator.validate(request(NAME));
            assertEquals(CAADecision.Outcome.ERROR, result.outcome());
            assertEquals(1, client.queries.size());
        }
    }

    @Test void productionBudgetEnforcesQueryAliasAndInterruptionLimits() throws Exception {
        var limits = new CAAPolicy.Limits(java.time.Duration.ofSeconds(5), java.time.Duration.ofSeconds(1), 1, 1, 1);
        var budget = new DefaultCAAValidator.Budget(limits);
        budget.reserveQuery(); budget.reserveAlias();
        assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                assertThrows(DNSLookupException.class, budget::reserveQuery).failure().reason());
        assertThrows(DNSLookupException.class, budget::reserveAlias);
        Thread.currentThread().interrupt();
        try {
            assertEquals(DNSLookupException.Reason.CANCELLED,
                    assertThrows(DNSLookupException.class, budget::check).failure().reason());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); }
    }

    @Test void requiredValidationAssuranceCannotDisappearSilently() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.mode = CAADNSClient.ValidationMode.DELEGATED_ENFORCING;
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
            assertEquals(CAADecision.Outcome.ERROR, validator.validate(request(NAME)).outcome());
        }
    }

    @Test void configurationDefaultsOffAndRejectsMisspelledEnablement() throws Exception {
        try (var gate = CAAIssuanceGate.open(new Properties(), getClass().getClassLoader())) {
            assertFalse(gate.isEnabled());
            assertEquals("issued", TestCAAIssuance.submit(gate, null, d -> fail("disabled check ran"), () -> "issued"));
        }
        var invalid = properties();
        invalid.setProperty("enabled", "ture");
        assertThrows(DNSLookupException.class, () -> CAAIssuanceGate.open(invalid, getClass().getClassLoader()));
        invalid.setProperty("enabled", "true"); invalid.setProperty("dns.class", "missing.Adapter");
        assertThrows(DNSLookupException.class, () -> CAAIssuanceGate.open(invalid, getClass().getClassLoader()));
    }

    @Test void issuerSubmissionRequiresAllowAndIsNotRetriedOrCachedAcrossRequests() throws Exception {
        Fixture.submissions.set(0);
        try (var gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            Fixture.last.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
            assertEquals("certificate", TestCAAIssuance.submit(gate, request(NAME), d -> {}, () -> { Fixture.submissions.incrementAndGet(); return "certificate"; }));
            Fixture.last.put("www.customer.test", record("www.customer.test", 0, "issue", ";"));
            assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, request(NAME), d -> {}, () -> { Fixture.submissions.incrementAndGet(); return "bad"; }));
            Fixture.last.error = true;
            assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, request(NAME), d -> {}, () -> { Fixture.submissions.incrementAndGet(); return "bad"; }));
            assertEquals(1, Fixture.submissions.get());
            assertEquals(3, Fixture.last.queries.size());
            gate.close();
            assertThrows(IllegalStateException.class, () -> TestCAAIssuance.submit(gate, request(NAME), d -> {}, () -> "bad"));
        }
    }

    @Test void wildcardFallsBackToIssueAndIssuewildDoesNotRestrictOrdinaryNames() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(name("www.customer.test", true))).outcome());
            client.put("www.customer.test", record("www.customer.test", 0, "issuewild", ";"));
            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(NAME)).outcome());
            assertEquals(CAADecision.Outcome.DENY, validator.validate(request(name("www.customer.test", true))).outcome());
        }
    }

    @Test void unknownCriticalPropertyOverridesAnOtherwiseValidGrant() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER),
                    record("www.customer.test", 129, "future", "opaque"));
            var decision = validator.validate(request(NAME));
            assertEquals(CAADecision.Outcome.DENY, decision.outcome());
            assertEquals(CAADecision.Reason.UNKNOWN_CRITICAL_PROPERTY, decision.names().get(0).reason());
        }
    }

    @Test void everyRequestedNameIsCheckedAndOneDenialBlocksTheAggregate() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
            client.put("api.customer.test", record("api.customer.test", 0, "issue", "other.test"));
            var decision = validator.validate(request(NAME, name("api.customer.test", false)));
            assertEquals(CAADecision.Outcome.DENY, decision.outcome());
            assertEquals(List.of(CAADecision.Outcome.ALLOW, CAADecision.Outcome.DENY),
                    decision.names().stream().map(CAADecision.NameDecision::outcome).toList());
            assertEquals(List.of("www.customer.test.", "api.customer.test."), client.queries);
        }
    }

    @Test void siblingNamesShareParentDiscoveryButRetainSeparateDecisions() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER));
            var decision = validator.validate(request(NAME, name("api.customer.test", false)));
            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
            assertEquals(2, decision.names().size());
            assertEquals(List.of("www.customer.test.", "customer.test.", "api.customer.test."), client.queries);
            assertTrue(decision.names().stream().allMatch(d -> d.relevantOwner().orElseThrow().equals(domain("customer.test"))));
        }
    }

    @Test void sharedParentPolicyUsesEachNamesOwnBindingContext() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER + ";validationmethods=dns-01"));
            var other = name("api.customer.test", false);
            var contexts = Map.of(NAME, new CAARequest.IssuanceContext(Optional.empty(), Optional.of("dns-01")),
                    other, new CAARequest.IssuanceContext(Optional.empty(), Optional.of("http-01")));
            var decision = validator.validate(new CAARequest(List.of(NAME, other), contexts));
            assertEquals(CAADecision.Outcome.ALLOW, decision.names().get(0).outcome());
            assertEquals(CAADecision.Outcome.DENY, decision.names().get(1).outcome());
            assertEquals(1, client.queries.stream().filter("customer.test."::equals).count());
        }
    }

    @Test void staleParentEvidenceCannotBeHiddenByAFreshLeafResponse() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            var parent = domain("customer.test");
            var stale = new CAADNSClient.ResponseEvidence("fixture", parent, 0, false,
                    CAADNSClient.DNSSECStatus.UNCHECKED, CAADNSClient.ValidationAssurance.NONE,
                    Instant.now().minusSeconds(9 * 3600), "fixture", Optional.empty());
            client.answers.put(parent, new CAADNSClient.LookupResult(parent, parent, CAADNSClient.LookupKind.RRSET,
                    List.of(new CAADNSClient.CAARecord(parent, 100000, 0, "issue", ISSUER.getBytes(StandardCharsets.US_ASCII))),
                    List.of(), List.of(stale), Optional.empty()));
            var decision = validator.validate(request(NAME));
            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            assertEquals(CAADecision.Reason.EXPIRED, decision.names().get(0).reason());
        }
    }

    @Test void secureFinalAnswerCannotCoverAnUnvalidatedEarlierObservation() throws Exception {
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.mode = CAADNSClient.ValidationMode.DELEGATED_ENFORCING;
            var secure = new CAADNSClient.ResponseEvidence("fixture", NAME.baseName(), 0, true,
                    CAADNSClient.DNSSECStatus.SECURE, CAADNSClient.ValidationAssurance.TRUSTED_RESOLVER,
                    Instant.now(), "fixture", Optional.empty());
            client.answers.put(NAME.baseName(), new CAADNSClient.LookupResult(NAME.baseName(), NAME.baseName(),
                    CAADNSClient.LookupKind.RRSET, List.of(record("www.customer.test", 0, "issue", ISSUER)), List.of(),
                    List.of(evidence(NAME.baseName()), secure), Optional.empty()));
            var decision = validator.validate(request(NAME));
            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE, decision.names().get(0).failure().orElseThrow().reason());
        }
    }

    @Test void controlAndNonAsciiIssueBytesNeverGrantAuthorization() throws Exception {
        for (byte value : new byte[] {0, 10, 13, (byte) 255}) {
            try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
                byte[] bytes = (ISSUER + "x").getBytes(StandardCharsets.US_ASCII);
                bytes[bytes.length - 1] = value;
                client.put("www.customer.test", new CAADNSClient.CAARecord(NAME.baseName(), 60, 0, "issue", bytes));
                assertEquals(CAADecision.Outcome.DENY, validator.validate(request(NAME)).outcome());
            }
        }
    }

    @Test void saturationRejectsWithoutDnsAndAdmissionRecoversAfterCompletion() throws Exception {
        var policy = policy();
        var entered = new CountDownLatch(policy.limits().maxConcurrentChecks());
        var release = new CountDownLatch(1);
        var client = new Fixture();
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        client.onLookup = () -> awaitLookup(entered, release);
        // CAAPolicy uses fixed production limits; occupy every allowed slot.
        var workers = Executors.newFixedThreadPool(policy.limits().maxConcurrentChecks());
        try (var validator = new DefaultCAAValidator(client, policy)) {
            var pending = new ArrayList<java.util.concurrent.Future<CAADecision>>();
            for (int i = 0; i < policy.limits().maxConcurrentChecks(); i++) pending.add(workers.submit(() -> validator.validate(request(NAME))));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            assertEquals(policy.limits().maxConcurrentChecks(), client.queries.size());
            var rejected = validator.validate(request(NAME));
            assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED, rejected.names().get(0).failure().orElseThrow().reason());
            assertEquals(policy.limits().maxConcurrentChecks(), client.queries.size());
            release.countDown();
            for (var check : pending) assertEquals(CAADecision.Outcome.ALLOW, check.get(2, TimeUnit.SECONDS).outcome());
            client.onLookup = () -> {};
            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(NAME)).outcome());
        } finally { release.countDown(); workers.shutdownNow(); }
    }

    @Test void shutdownDuringLookupCannotReturnAnAllowDecision() throws Exception {
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var client = new Fixture();
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        client.onLookup = () -> awaitLookup(entered, release);
        var executor = Executors.newSingleThreadExecutor();
        try (var validator = new DefaultCAAValidator(client, policy())) {
            var pending = executor.submit(() -> validator.validate(request(NAME)));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            validator.close(); validator.close();
            release.countDown();
            var result = pending.get(2, TimeUnit.SECONDS);
            assertEquals(CAADecision.Outcome.ERROR, result.outcome());
            assertEquals(DNSLookupException.Reason.CANCELLED, result.names().get(0).failure().orElseThrow().reason());
            assertEquals(1, client.closes.get());
        } finally { release.countDown(); executor.shutdownNow(); }
    }

    @Test void largeParameterTagsAreRejectedWithoutOverflowAndDoNotOverrideOtherGrants() throws Exception {
        for (int repeats : List.of(5000, 32000)) {
            try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
                String value = ISSUER + ";" + "a-".repeat(repeats) + "a=x";
                client.put("www.customer.test", record("www.customer.test", 0, "issue", value));
                assertEquals(CAADecision.Outcome.DENY, validator.validate(request(NAME)).outcome());
                client.put("www.customer.test", record("www.customer.test", 0, "issue", value),
                        record("www.customer.test", 0, "issue", ISSUER));
                assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(NAME)).outcome());
            }
        }
    }

    @Test void largeMethodListsAreParsedCompletelyWithoutOverflow() throws Exception {
        var context = new CAARequest.IssuanceContext(Optional.empty(), Optional.of("dns-01"));
        var request = new CAARequest(List.of(NAME), Map.of(NAME, context));
        for (int repeats : List.of(5000, 32000)) {
            try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
                String value = ISSUER + ";validationmethods=dns-01," + "x,".repeat(repeats) + "http-01";
                client.put("www.customer.test", record("www.customer.test", 0, "issue", value));
                assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request).outcome());
                for (String suffix : List.of(",", ",bad_label", ",bad label")) {
                    client.put("www.customer.test", record("www.customer.test", 0, "issue", value + suffix));
                    assertEquals(CAADecision.Outcome.DENY, validator.validate(request).outcome());
                }
            }
        }
    }

    @Test void parameterWhitespaceAndSyntaxFollowTheCaaGrammar() throws Exception {
        var context = new CAARequest.IssuanceContext(Optional.empty(), Optional.of("dns-01"));
        var request = new CAARequest(List.of(NAME), Map.of(NAME, context));
        try (var client = new Fixture(); var validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue",
                    "\t" + ISSUER + " ; \tvalidationmethods\t = \tdns-01\t"));
            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request).outcome());
            for (String parameter : List.of("-key=x", "key-=x", "key name=x", "key\tname=x", "=x", "key=has space")) {
                client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER + ";" + parameter));
                assertEquals(CAADecision.Outcome.DENY, validator.validate(request).outcome(), parameter);
            }
        }
    }

    private static void awaitLookup(CountDownLatch entered, CountDownLatch release) {
        entered.countDown();
        try { assertTrue(release.await(3, TimeUnit.SECONDS)); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
    }

    private static Properties properties() {
        Properties p = new Properties();
        p.setProperty("enabled", "true"); p.setProperty("issuerIdentifiers", ISSUER);
        p.setProperty("dns.class", Fixture.class.getName());
        return p;
    }
    private static CAAPolicy policy() { return new CAAPolicy(Set.of(ISSUER)); }
    private static CAARequest request(CAARequest.CertificateName... names) { return new CAARequest(List.of(names), Map.of()); }
    private static DNSDomainName domain(String text) { return new DNSDomainName(text + "."); }
    private static CAARequest.CertificateName name(String text, boolean wildcard) { return new CAARequest.CertificateName(domain(text), wildcard); }
    private static CAADNSClient.CAARecord record(String owner, int flags, String tag, String value) {
        return new CAADNSClient.CAARecord(domain(owner), 60, flags, tag, value.getBytes(StandardCharsets.US_ASCII));
    }
    private static CAADNSClient.ResponseEvidence evidence(DNSDomainName candidate) {
        return new CAADNSClient.ResponseEvidence("fixture", candidate, 0, false, CAADNSClient.DNSSECStatus.UNCHECKED,
                CAADNSClient.ValidationAssurance.NONE, Instant.now(), "fixture", Optional.empty());
    }

    /** Config-loadable test provider, never included in the deliverable JAR. */
    public static final class Fixture implements CAADNSClientProvider, CAADNSClient {
        static Fixture last;
        static final AtomicInteger submissions = new AtomicInteger();
        final List<String> queries = new java.util.concurrent.CopyOnWriteArrayList<>();
        final Map<DNSDomainName, LookupResult> answers = new HashMap<>();
        boolean error;
        Runnable onLookup = () -> {};
        final AtomicInteger closes = new AtomicInteger();
        ValidationMode mode = ValidationMode.UNCHECKED;
        @Override public ValidationMode validationMode() { return mode; }
        @Override public CAADNSClient open(Config config) { last = this; return this; }
        @Override public LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget) throws DNSLookupException {
            budget.reserveQuery(); queries.add(candidate.asciiAbsoluteName());
            onLookup.run();
            if (error) throw DefaultCAAValidator.failure(DNSLookupException.Reason.RCODE_FAILURE, "fixture failure");
            return answers.getOrDefault(candidate, new LookupResult(candidate, candidate, LookupKind.NODATA,
                    List.of(), List.of(), List.of(evidence(candidate)),
                    Optional.empty()));
        }
        void put(String name, CAARecord... records) {
            var owner = domain(name);
            answers.put(owner, new LookupResult(owner, owner, LookupKind.RRSET, List.of(records), List.of(),
                    List.of(evidence(owner)), Optional.empty()));
        }
        @Override public void close() { closes.incrementAndGet(); }
    }
}

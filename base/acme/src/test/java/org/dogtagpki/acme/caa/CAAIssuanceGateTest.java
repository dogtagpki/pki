// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests the boundary between CAA evaluation and permission to submit an
 * issuance request. The gate applies instance configuration, owns the
 * validator, reports decisions and blocks submission when approval is unusable.
 * An in-memory DNS provider drives the real engine, and a recording callback
 * stands in for the issuer. This covers check-then-submit behavior without
 * exercising ACME HTTP processing or actual CA signing.
 */
class CAAIssuanceGateTest {
    private static final DNSDomainName NAME = new DNSDomainName("www.example.com.");
    private static final CAARequest REQUEST = new CAARequest(
            List.of(new CAARequest.CertificateName(NAME, false)), Map.of());

    @BeforeEach
    void reset() {
        TestDNSProvider.opens.set(0);
        TestDNSProvider.closes.set(0);
        TestDNSProvider.lookups.set(0);
        TestDNSProvider.settings = Map.of();
        TestDNSProvider.issuer = "ca.example";
        TestDNSProvider.deniedName = null;
        TestDNSProvider.onLookup = () -> {};
        TestDNSProvider.error = false;
        TestDNSProvider.untrusted = false;
        TestDNSProvider.absent = false;
    }

    /**
     * Disable CAA while supplying an absent adapter and unusable settings.
     * Submission must proceed without opening DNS or calling the decision observer.
     */
    @Test
    void disabledPolicyDoesNotLoadAnAbsentProviderOrValidateItsSettings() throws Exception {
        Properties properties = properties();
        properties.setProperty("enabled", "false");
        properties.setProperty("dns.class", "not.installed.Provider");
        properties.setProperty("issuerIdentifiers", "not an issuer");
        properties.setProperty("dns.settings.not-supported", "private-value");

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
            String result = TestCAAIssuance.submit(gate, null,
                    decision -> fail("Disabled policy observed"), () -> "issued");

            assertFalse(gate.isEnabled());
            assertEquals("issued", result);
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Supply unknown configuration keys, including a misspelled enable flag.
     * Reject them rather than silently leaving enforcement disabled.
     */
    @Test
    void misspelledAndLegacySettingsFailBeforeOpeningAProvider() {
        for (String key : List.of("enabeld", "validationMode", "version", "params.accept", "dns.server")) {
            Properties properties = properties();
            properties.setProperty(key, "value");
            if (key.equals("enabeld")) {
                properties.remove("enabled");
            }

            DNSLookupException error = assertThrows(DNSLookupException.class,
                    () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
            assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Programmatic Properties entries must not disappear during string-only
     * enumeration. Exercise explicit values and inherited defaults alike.
     */
    @Test
    void nonStringSettingsFailBeforeDefaultsCanDisableCaa() {
        record InvalidSetting(Object key, Object value) {}
        List<InvalidSetting> cases = List.of(
                new InvalidSetting("enabled", Boolean.TRUE),
                new InvalidSetting("issuerIdentifiers", 123),
                new InvalidSetting("dns.class", 123),
                new InvalidSetting("dns.settings.port", 1053),
                new InvalidSetting("unknown", Boolean.FALSE),
                new InvalidSetting(123, "value"));

        for (InvalidSetting test : cases) {
            Properties invalid = new Properties();
            invalid.put(test.key(), test.value());
            for (Properties settings : List.of(invalid, new Properties(invalid))) {
                DNSLookupException error = assertThrows(DNSLookupException.class,
                        () -> CAAIssuanceGate.open(settings, getClass().getClassLoader()), test.toString());
                assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason(), test.toString());
            }
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Valid string defaults still enable checking. An explicit malformed value
     * must be rejected even if getProperty() would fall back to a string default.
     */
    @Test
    void stringDefaultsWorkButCannotHideMalformedExplicitValues() throws Exception {
        Properties settings = new Properties(properties());
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(settings, getClass().getClassLoader())) {
            assertTrue(gate.isEnabled());
            gate.check(REQUEST, decision -> assertEquals(CAADecision.Outcome.ALLOW, decision.outcome()));
        }

        settings.put("enabled", Boolean.TRUE);
        DNSLookupException error = assertThrows(DNSLookupException.class,
                () -> CAAIssuanceGate.open(settings, getClass().getClassLoader()));
        assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
        assertEquals(1, TestDNSProvider.opens.get());
    }

    /**
     * An inherited Boolean must not be skipped in favor of a deeper string
     * default. Exercise the enable flag and provider settings through both an
     * enabled and disabled fallback before any provider can open.
     */
    @Test
    void inheritedMalformedValuesCannotFallBackToStrings() {
        for (String fallback : List.of("true", "false")) {
            for (String key : List.of("enabled", "issuerIdentifiers", "dns.class", "dns.settings.port")) {
                Properties defaults = properties();
                defaults.setProperty("enabled", fallback);
                // Keep fallback values valid so only the inherited type can fail.
                if (key.equals("dns.settings.port")) {
                    defaults.setProperty(key, "1053");
                }
                Properties malformed = new Properties(defaults);
                malformed.put(key, Boolean.TRUE);
                Properties settings = new Properties(malformed);

                DNSLookupException error = assertThrows(DNSLookupException.class,
                        () -> CAAIssuanceGate.open(settings, getClass().getClassLoader()),
                        key + " with enabled=" + fallback);
                assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
            }
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Try empty list elements and URL-shaped issuers in enabled configuration.
     * All must fail before opening DNS, including leading and trailing commas.
     */
    @Test
    void malformedIssuerListsCannotOpenDnsOrBecomePermissive() {
        for (String value : List.of("", ",ca.example", "ca.example,", "ca.example,,other.test", "https://ca.example")) {
            Properties properties = properties();
            properties.setProperty("issuerIdentifiers", value);

            assertThrows(DNSLookupException.class,
                    () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Configure two issuer identifiers and namespaced adapter settings. Verify
     * that settings are copied, the prefix is removed, and the alternate issuer grants.
     */
    @Test
    void acceptsTrimmedMultipleIssuersAndPreservesProviderSettings() throws Exception {
        Properties properties = properties();
        properties.setProperty("issuerIdentifiers", " ca.example , OTHER.example ");
        properties.setProperty("dns.settings.server", "127.0.0.1");
        properties.setProperty("dns.settings.port", "1053");
        TestDNSProvider.issuer = "other.example";

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
            assertEquals(Map.of("server", "127.0.0.1", "port", "1053"), TestDNSProvider.settings);
            properties.setProperty("dns.settings.server", "changed-after-open");

            assertEquals("127.0.0.1", TestDNSProvider.settings.get("server"));
            gate.check(REQUEST, decision -> assertEquals(CAADecision.Outcome.ALLOW, decision.outcome()));
        }
    }

    /**
     * Preserve two distinct identities, including wildcard status, and report
     * their decisions before exactly one submission callback.
     */
    @Test
    void observesBeforeExactlyOneSubmission() throws Exception {
        List<String> events = new ArrayList<>();
        List<CAARequest.CertificateName> names = List.of(new CAARequest.CertificateName(NAME, false),
                new CAARequest.CertificateName(new DNSDomainName("other.example.net."), true));
        CAARequest request = new CAARequest(names, Map.of());
        AtomicInteger submissions = new AtomicInteger();
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            TestCAAIssuance.submit(gate, request, decision -> {
                events.add("observe");
                assertEquals(names, decision.names().stream().map(CAADecision.NameDecision::name).toList());
                assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
            }, () -> {
                events.add("submit");
                return submissions.incrementAndGet();
            });
            assertEquals(List.of("observe", "submit"), events);
            assertEquals(1, submissions.get());
        }
    }

    /**
     * Deny only the second identity. The observer must retain both exact names
     * and their separate outcomes, and no submission callback may run.
     */
    @Test
    void deniedSecondIdentityIsObservedAndBlocksSubmission() throws Exception {
        DNSDomainName other = new DNSDomainName("other.example.net.");
        List<CAARequest.CertificateName> names = List.of(new CAARequest.CertificateName(NAME, false),
                new CAARequest.CertificateName(other, true));
        CAARequest request = new CAARequest(names, Map.of());
        TestDNSProvider.deniedName = other;
        AtomicInteger submissions = new AtomicInteger();
        List<String> events = new ArrayList<>();

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            CAAIssuanceGate.CAAApprovalException error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, request, decision -> {
                        events.add("observe");
                        assertEquals(names, decision.names().stream().map(CAADecision.NameDecision::name).toList());
                        assertEquals(List.of(CAADecision.Outcome.ALLOW, CAADecision.Outcome.DENY),
                                decision.names().stream().map(CAADecision.NameDecision::outcome).toList());
                    }, submissions::incrementAndGet));
            assertEquals(CAAIssuanceGate.RejectionReason.EVALUATION, error.reason());
            assertEquals(CAADecision.Reason.ISSUER_NOT_AUTHORIZED, error.decision().names().get(1).reason());
            assertEquals(List.of("observe"), events);
            assertEquals(0, submissions.get());
        }
    }

    /**
     * Make the decision observer throw and verify that the issuer is not called.
     * A subsequent attempt with a working observer must still be able to submit.
     */
    @Test
    void observerFailureSuppressesSubmissionAndDoesNotPoisonTheNextCheck() throws Exception {
        AtomicInteger submissions = new AtomicInteger();

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            Consumer<CAADecision> failingObserver = decision -> {
                throw new IllegalStateException("Decision observer failed");
            };

            assertThrows(IllegalStateException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, failingObserver, submissions::incrementAndGet));
            assertEquals(0, submissions.get());
            int submitted = TestCAAIssuance.submit(gate, REQUEST,
                    decision -> assertEquals(CAADecision.Outcome.ALLOW, decision.outcome()),
                    submissions::incrementAndGet);

            assertEquals(1, submitted);
        }
    }

    /**
     * Interrupt after validation has allowed, while reporting its evidence.
     * The gate must refuse handoff without clearing the interruption flag.
     */
    @Test
    void observerInterruptionBlocksSubmissionAndPreservesTheFlag() throws Exception {
        AtomicInteger submissions = new AtomicInteger();
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            try {
                CAAIssuanceGate.CAAApprovalException error = assertThrows(
                        CAAIssuanceGate.CAAApprovalException.class,
                        () -> TestCAAIssuance.submit(gate, REQUEST,
                                decision -> Thread.currentThread().interrupt(), submissions::incrementAndGet));

                assertEquals(CAAIssuanceGate.RejectionReason.CANCELLED, error.reason());
                assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
                assertTrue(Thread.currentThread().isInterrupted());
                assertEquals(0, submissions.get());
            } finally {
                Thread.interrupted();
            }

            TestCAAIssuance.submit(gate, REQUEST, decision -> {}, submissions::incrementAndGet);
            assertEquals(1, submissions.get());
        }
    }

    /** Logging and issuer preparation share the original five-second deadline. */
    @Test
    void submissionUsesTheOriginalAttemptDeadline() throws Exception {
        MutableClock clock = new MutableClock();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            var check = gate.check(REQUEST, decision -> clock.elapsedNanos += Duration.ofSeconds(4).toNanos());
            check.run();
            clock.elapsedNanos += Duration.ofSeconds(1).toNanos();
            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED,
                    assertThrows(CAAIssuanceGate.CAAApprovalException.class, check::run).reason());
            gate.check(REQUEST, decision -> {}).run();
            var expired = assertThrows(CAAIssuanceGate.CAAApprovalException.class, () ->
                    gate.check(REQUEST, decision -> clock.elapsedNanos += Duration.ofSeconds(5).toNanos()));
            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, expired.reason());
        }
    }

    /** A pause after initial approval must be caught by the helper's final guard. */
    @Test
    void checkThenSubmitHelperRejectsExpiryBeforeTheCallback() throws Exception {
        MutableClock clock = new MutableClock();
        var validator = new DefaultCAAValidator(new TestDNSProvider(),
                new CAAPolicy(Set.of("ca.example")), clock, () -> clock.elapsedNanos);
        try (var gate = new CAAIssuanceGate(validator, () -> {
            long sample = clock.elapsedNanos;
            clock.elapsedNanos += Duration.ofSeconds(5).toNanos();
            return sample;
        })) {
            var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {},
                            () -> fail("Expired attempt reached the issuer")));
            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
        }
    }

    /** Closing during the last clock read must block an otherwise fresh approval. */
    @Test
    void shutdownDuringFinalElapsedReadBlocksSubmission() throws Exception {
        MutableClock clock = new MutableClock();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> clock.onElapsedRead = gate::close,
                            () -> fail("Submitted after shutdown")));
            assertEquals(CAAIssuanceGate.RejectionReason.CLOSED, error.reason());
            assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
        }
    }

    /** Interruption during the last clock read remains visible to the caller. */
    @Test
    void interruptionDuringFinalElapsedReadBlocksSubmission() throws Exception {
        MutableClock clock = new MutableClock();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST,
                            decision -> clock.onElapsedRead = Thread.currentThread()::interrupt,
                            () -> fail("Interrupted caller submitted")));
            assertEquals(CAAIssuanceGate.RejectionReason.CANCELLED, error.reason());
            assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    /** Shares one controllable elapsed clock between the validator and gate. */
    private CAAIssuanceGate timedGate(MutableClock clock) {
        CAAPolicy policy = new CAAPolicy(Set.of("ca.example"));
        CAAValidator validator = new DefaultCAAValidator(
                new TestDNSProvider(), policy, clock, () -> clock.elapsedNanos);
        return new CAAIssuanceGate(validator, clock::readElapsed);
    }

    /**
     * Keeps wall time independent of elapsed time to model host-clock corrections.
     */
    private static final class MutableClock extends Clock {
        Instant wallTime = Instant.parse("2026-11-23T12:00:00Z");
        long elapsedNanos;
        Runnable onElapsedRead = () -> {};

        long readElapsed() {
            onElapsedRead.run();
            return elapsedNanos;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return Clock.fixed(wallTime, zone);
        }

        @Override
        public Instant instant() {
            return wallTime;
        }
    }

    /**
     * Close the gate from its observer after an ALLOW evaluation. The final
     * gate check must reject submission; repeated close calls must close DNS only once.
     */
    @Test
    void closeDuringObservationBlocksSubmissionAndClosesTheClientOnce() throws Exception {
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            CAAIssuanceGate.CAAApprovalException error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST,
                            decision -> gate.close(), () -> fail("Closed gate submitted")));

            assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
            assertEquals(CAAIssuanceGate.RejectionReason.CLOSED, error.reason());
            gate.close();

            assertEquals(1, TestDNSProvider.closes.get());
        }
        assertEquals(1, TestDNSProvider.closes.get());
    }

    /** Disabled guards still honor shutdown after preparation, while leaving interruption to the host. */
    @Test
    void disabledGuardRechecksShutdownWithoutCallingDnsOrObserver() throws Exception {
        try (var gate = CAAIssuanceGate.open(new Properties(), getClass().getClassLoader())) {
            var guard = gate.check(null, decision -> fail("Disabled gate invoked observer"));
            Thread.currentThread().interrupt();
            try {
                guard.run();
                assertTrue(Thread.currentThread().isInterrupted());
                gate.close();
                assertThrows(IllegalStateException.class, guard::run);
                assertTrue(Thread.currentThread().isInterrupted());
                assertEquals(0, TestDNSProvider.opens.get());
                assertEquals(0, TestDNSProvider.lookups.get());
            } finally {
                Thread.interrupted();
            }
        }
    }

    /**
     * Close a disabled gate, then try submission. Even a disabled gate must
     * reject use after shutdown instead of bypassing its lifecycle checks.
     */
    @Test
    void closingADisabledGateDoesNotEnableAnIssuanceBypass() throws Exception {
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(new Properties(), getClass().getClassLoader())) {
            gate.close();

            assertThrows(IllegalStateException.class,
                    () -> TestCAAIssuance.submit(gate, null,
                            decision -> fail("Closed gate observed CAA"),
                            () -> fail("Closed disabled gate submitted")));
        }
    }

    /**
     * No enabled setting means no CAA check and no provider allocation.
     */
    @Test
    void configurationDefaultsOff() throws Exception {
        Properties properties = new Properties();

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
            gate.check(null, decision -> fail("Disabled gate checked CAA"));

            assertFalse(gate.isEnabled());
            assertEquals(0, TestDNSProvider.opens.get());
        }
    }

    /**
     * A misspelled enabled value must fail before a DNS provider is opened.
     */
    @Test
    void invalidEnabledValueFailsConfiguration() {
        Properties properties = properties();
        properties.setProperty("enabled", "ture");

        DNSLookupException failure = assertThrows(DNSLookupException.class,
                () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
        assertEquals(DNSLookupException.Reason.CONFIGURATION, failure.failure().reason());
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Explicit enablement must fail when the selected provider is not installed.
     */
    @Test
    void enabledWithMissingProviderFailsConfiguration() {
        Properties properties = properties();
        properties.setProperty("dns.class", "missing.Adapter");

        DNSLookupException failure = assertThrows(DNSLookupException.class,
                () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
        assertEquals(DNSLookupException.Reason.CONFIGURATION, failure.failure().reason());
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Change the fixture from grant to denial to DNS error between attempts.
     * Every attempt must consult DNS, and only the grant can invoke the issuer.
     */
    @Test
    void submissionRequiresAllowWithoutCachingAcrossRequests() throws Exception {
        AtomicInteger submissions = new AtomicInteger();
        Consumer<CAADecision> observer = decision -> {
            // This test checks admission, not the contents of logged decisions.
        };

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            int submitted = TestCAAIssuance.submit(gate, REQUEST, observer, submissions::incrementAndGet);

            assertEquals(1, submitted);

            TestDNSProvider.issuer = ";";

            CAAIssuanceGate.CAAApprovalException denial = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, observer, submissions::incrementAndGet));
            assertEquals(CAADecision.Outcome.DENY, denial.decision().outcome());
            assertEquals(CAAIssuanceGate.RejectionReason.EVALUATION, denial.reason());

            TestDNSProvider.error = true;

            CAAIssuanceGate.CAAApprovalException failure = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, observer, submissions::incrementAndGet));
            assertEquals(CAADecision.Outcome.ERROR, failure.decision().outcome());
            assertEquals(CAAIssuanceGate.RejectionReason.EVALUATION, failure.reason());
            assertEquals(1, submissions.get());
            assertEquals(3, TestDNSProvider.lookups.get());
            gate.close();

            assertThrows(IllegalStateException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, observer, submissions::incrementAndGet));
            assertEquals(1, submissions.get());
        }
    }

    /**
     * Untrusted grants and apparent absence must both stop at the gate. Either
     * response could hide restrictions; neither may reach issuer submission.
     */
    @Test
    void missingAssuranceBlocksSubmissionForGrantsAndAbsence() throws Exception {
        for (boolean absent : List.of(false, true)) {
            TestDNSProvider.untrusted = true;
            TestDNSProvider.absent = absent;
            TestDNSProvider.lookups.set(0);
            AtomicInteger submissions = new AtomicInteger();
            try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
                CAAIssuanceGate.CAAApprovalException failure = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                        () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {}, submissions::incrementAndGet));

                String scenario = absent ? "absence" : "grant";
                assertEquals(CAADecision.Outcome.ERROR, failure.decision().outcome(), scenario);
                assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                        failure.decision().names().get(0).failure().orElseThrow().reason(), scenario);
                assertEquals(0, submissions.get(), scenario);
                assertEquals(1, TestDNSProvider.lookups.get(), scenario);
            }
        }
    }

    private Properties properties() {
        Properties properties = new Properties();
        properties.setProperty("enabled", "true");
        properties.setProperty("issuerIdentifiers", "ca.example");
        properties.setProperty("dns.class", TestDNSProvider.class.getName());
        return properties;
    }

    /**
     * Public no-argument provider for class-name loading. Each test resets its
     * policy, timestamps and counters. No real DNS traffic occurs.
     */
    public static final class TestDNSProvider implements CAADNSClientProvider, CAADNSClient {
        static final AtomicInteger opens = new AtomicInteger();
        static final AtomicInteger closes = new AtomicInteger();
        static final AtomicInteger lookups = new AtomicInteger();
        static Map<String, String> settings;
        static String issuer;
        static DNSDomainName deniedName;
        static Runnable onLookup;
        static boolean error;
        static boolean untrusted;
        static boolean absent;

        @Override
        public CAADNSClient open(Config config) {
            opens.incrementAndGet();
            settings = config.settings();
            return this;
        }

        @Override
        public LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget) throws DNSLookupException {
            budget.reserveQuery();
            lookups.incrementAndGet();
            onLookup.run();
            if (error) {
                throw DefaultCAAValidator.failure(DNSLookupException.Reason.UNREACHABLE, "Fixture DNS unavailable");
            }
            String authorizedIssuer = candidate.equals(deniedName) ? "other-ca.example" : issuer;
            CAARecord record = new CAARecord(candidate, 60, 0, "issue",
                    authorizedIssuer.getBytes(StandardCharsets.US_ASCII));
            ValidationStatus status = untrusted ? ValidationStatus.UNTRUSTED : ValidationStatus.UNCLASSIFIED;
            ResponseEvidence response = new ResponseEvidence("fixture", candidate, 0, false,
                    status, "fixture", Optional.empty());
            LookupKind kind = absent ? LookupKind.NODATA : LookupKind.RRSET;
            List<CAARecord> records = absent ? List.of() : List.of(record);
            return new LookupResult(candidate, candidate, kind,
                    records, List.of(), List.of(response), Optional.empty());
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }
    }
}

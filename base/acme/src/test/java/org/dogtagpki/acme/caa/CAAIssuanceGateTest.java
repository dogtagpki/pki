// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.Callable;
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
        TestDNSProvider.receivedAt = Instant.now();
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

            DNSLookupException error = assertThrows(DNSLookupException.class,
                    () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
            assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
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
     * Record observer and submission callbacks in a list, then make submission
     * throw. Expect observer first, one submission and the original issuer exception.
     */
    @Test
    void observesBeforeExactlyOneSubmissionAndPropagatesIssuerFailure() throws Exception {
        List<String> events = new ArrayList<>();
        IOException failure = new IOException("CA is unavailable");

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            Callable<String> issuer = () -> {
                events.add("submit");
                throw failure;
            };
            IOException actual = assertThrows(IOException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> events.add("observe"), issuer));
            assertSame(failure, actual);
            assertEquals(List.of("observe", "submit"), events);
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
     * Return DNS evidence received nine hours ago. Evaluation must report
     * expiry to the observer, and the gate must block the submission callback.
     */
    @Test
    void expiredEvidenceIsObservedButCannotReachTheIssuer() throws Exception {
        TestDNSProvider.receivedAt = Instant.now().minusSeconds(9 * 3600);

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            AtomicInteger observations = new AtomicInteger();

            CAAIssuanceGate.CAAApprovalException error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST,
                            decision -> observations.incrementAndGet(),
                            () -> fail("Expired decision submitted")));
            assertEquals(CAADecision.Outcome.ERROR, error.decision().outcome());
            assertEquals(CAADecision.Reason.EXPIRED, error.decision().names().get(0).reason());
            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
            assertEquals(1, observations.get());
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
     * Missing assurance must block the issuer even if DNS returns an unrestricted
     * grant, since a forged answer could have removed account/method restrictions.
     */
    @Test
    void missingAssuranceOnUnrestrictedGrantBlocksSubmission() throws Exception {
        TestDNSProvider.untrusted = true;
        AtomicInteger submissions = new AtomicInteger();

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            CAAIssuanceGate.CAAApprovalException failure = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {}, submissions::incrementAndGet));

            assertEquals(CAADecision.Outcome.ERROR, failure.decision().outcome());
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                    failure.decision().names().get(0).failure().orElseThrow().reason());
            assertEquals(0, submissions.get());
            assertEquals(1, TestDNSProvider.lookups.get());
        }
    }

    /**
     * Apparent absence without assurance must not permit parent traversal or
     * submission. A forged response could otherwise hide all CAA restrictions.
     */
    @Test
    void missingAssuranceOnAbsenceBlocksSubmission() throws Exception {
        TestDNSProvider.untrusted = true;
        TestDNSProvider.absent = true;
        AtomicInteger submissions = new AtomicInteger();

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            CAAIssuanceGate.CAAApprovalException failure = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {}, submissions::incrementAndGet));

            assertEquals(CAADecision.Outcome.ERROR, failure.decision().outcome());
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                    failure.decision().names().get(0).failure().orElseThrow().reason());
            assertEquals(0, submissions.get());
            assertEquals(1, TestDNSProvider.lookups.get());
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
        static Instant receivedAt;
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
            if (error) {
                throw DefaultCAAValidator.failure(DNSLookupException.Reason.UNREACHABLE, "Fixture DNS unavailable");
            }
            CAARecord record = new CAARecord(candidate, 60, 0, "issue", issuer.getBytes(StandardCharsets.US_ASCII));
            ValidationStatus status = untrusted ? ValidationStatus.UNTRUSTED : ValidationStatus.UNCLASSIFIED;
            ResponseEvidence response = new ResponseEvidence("fixture", candidate, 0, false,
                    status, receivedAt, "fixture", Optional.empty());
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

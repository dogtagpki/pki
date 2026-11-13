// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later
package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Security-sensitive tests for configuration, audit ordering and issuer admission. */
class CAAIssuanceGateTest {
    private static final DNSDomainName NAME = new DNSDomainName("www.example.com.");
    private static final CAARequest REQUEST = new CAARequest(List.of(new CAARequest.CertificateName(NAME, false)), Map.of());

    @BeforeEach void reset() {
        Provider.opens.set(0); Provider.closes.set(0); Provider.settings = Map.of();
        Provider.issuer = "ca.example"; Provider.receivedAt = Instant.now();
    }

    @Test void disabledPolicyDoesNotLoadAnAbsentProviderOrValidateItsSettings() throws Exception {
        var properties = properties();
        properties.setProperty("enabled", "false");
        properties.setProperty("dns.class", "not.installed.Provider");
        properties.setProperty("issuerIdentifiers", "not an issuer");
        properties.setProperty("dns.settings.not-supported", "private-value");
        try (var gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
            assertFalse(gate.isEnabled());
            assertEquals("issued", TestCAAIssuance.submit(gate, null, d -> fail("Disabled policy audited"), () -> "issued"));
        }
        assertEquals(0, Provider.opens.get());
    }

    @Test void misspelledAndLegacySettingsFailBeforeOpeningAProvider() {
        for (String key : List.of("enabeld", "validationMode", "version", "params.accept", "dns.server")) {
            var properties = properties(); properties.setProperty(key, "value");
            var error = assertThrows(DNSLookupException.class,
                    () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
            assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
        }
        assertEquals(0, Provider.opens.get());
    }

    @Test void malformedIssuerListsCannotOpenDnsOrBecomePermissive() {
        for (String value : List.of("", ",ca.example", "ca.example,", "ca.example,,other.test", "https://ca.example")) {
            var properties = properties(); properties.setProperty("issuerIdentifiers", value);
            assertThrows(DNSLookupException.class,
                    () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
        }
        assertEquals(0, Provider.opens.get());
    }

    @Test void acceptsTrimmedMultipleIssuersAndPreservesProviderSettings() throws Exception {
        var properties = properties();
        properties.setProperty("issuerIdentifiers", " ca.example , OTHER.example ");
        properties.setProperty("dns.settings.server", "127.0.0.1");
        properties.setProperty("dns.settings.port", "1053");
        Provider.issuer = "other.example";
        try (var gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
            assertEquals(Map.of("server", "127.0.0.1", "port", "1053"), Provider.settings);
            properties.setProperty("dns.settings.server", "changed-after-open");
            assertEquals("127.0.0.1", Provider.settings.get("server"));
            assertEquals("issued", TestCAAIssuance.submit(gate, REQUEST, d -> {}, () -> "issued"));
        }
    }

    @Test void auditsBeforeExactlyOneSubmissionAndPropagatesIssuerFailure() throws Exception {
        var events = new ArrayList<String>();
        var failure = new IOException("CA is unavailable");
        try (var gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            var actual = assertThrows(IOException.class, () -> TestCAAIssuance.submit(gate, REQUEST,
                    d -> events.add("audit"), () -> { events.add("submit"); throw failure; }));
            assertSame(failure, actual);
            assertEquals(List.of("audit", "submit"), events);
        }
    }

    @Test void auditFailureSuppressesSubmissionAndDoesNotPoisonTheNextCheck() throws Exception {
        var submissions = new AtomicInteger();
        try (var gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            assertThrows(IllegalStateException.class, () -> TestCAAIssuance.submit(gate, REQUEST,
                    d -> { throw new IllegalStateException("Audit sink failed"); }, submissions::incrementAndGet));
            assertEquals(0, submissions.get());
            assertEquals(1, TestCAAIssuance.submit(gate, REQUEST, d -> {}, submissions::incrementAndGet));
        }
    }

    @Test void expiredEvidenceIsAuditedButCannotReachTheIssuer() throws Exception {
        Provider.receivedAt = Instant.now().minusSeconds(9 * 3600);
        try (var gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            var audits = new AtomicInteger();
            var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, d -> audits.incrementAndGet(), () -> fail("Expired decision submitted")));
            assertEquals(CAADecision.Outcome.ERROR, error.decision().outcome());
            assertEquals(CAADecision.Reason.EXPIRED, error.decision().names().get(0).reason());
            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
            assertEquals(1, audits.get());
        }
    }

    @Test void closeDuringAuditBlocksSubmissionAndClosesTheClientOnce() throws Exception {
        try (var gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, d -> gate.close(), () -> fail("Closed gate submitted")));
            assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
            assertEquals(CAAIssuanceGate.RejectionReason.CLOSED, error.reason());
            gate.close();
            assertEquals(1, Provider.closes.get());
        }
        assertEquals(1, Provider.closes.get());
    }

    @Test void closingADisabledGateDoesNotEnableAnIssuanceBypass() throws Exception {
        try (var gate = CAAIssuanceGate.open(new Properties(), getClass().getClassLoader())) {
            gate.close();
            assertThrows(IllegalStateException.class,
                    () -> TestCAAIssuance.submit(gate, null, d -> {}, () -> fail("Closed disabled gate submitted")));
        }
    }

    private Properties properties() {
        var properties = new Properties();
        properties.setProperty("enabled", "true");
        properties.setProperty("issuerIdentifiers", "ca.example");
        properties.setProperty("dns.class", Provider.class.getName());
        return properties;
    }

    /** Config-loadable fixture; collections and counters remain test-only. */
    public static final class Provider implements CAADNSClientProvider, CAADNSClient {
        static final AtomicInteger opens = new AtomicInteger();
        static final AtomicInteger closes = new AtomicInteger();
        static Map<String, String> settings;
        static String issuer;
        static Instant receivedAt;
        @Override public ValidationMode validationMode() { return ValidationMode.UNCHECKED; }
        @Override public CAADNSClient open(Config config) {
            opens.incrementAndGet(); settings = config.settings(); return this;
        }
        @Override public LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget) throws DNSLookupException {
            budget.reserveQuery();
            return new LookupResult(candidate, candidate, LookupKind.RRSET,
                    List.of(new CAARecord(candidate, 60, 0, "issue", issuer.getBytes(StandardCharsets.US_ASCII))),
                    List.of(), List.of(new ResponseEvidence("fixture", candidate, 0, false,
                            DNSSECStatus.UNCHECKED, ValidationAssurance.NONE, receivedAt, "fixture", Optional.empty())), Optional.empty());
        }
        @Override public void close() { closes.incrementAndGet(); }
    }
}

// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

/** Checks CAA policy inputs, immutable models and DNS evidence consistency. */
public class CAAContractsTest {

    private static final DNSDomainName NAME = new DNSDomainName("www.example.test.");

    @Test
    void validatesIssuerIdentifiersWithoutChangingConfiguredSpelling() {
        Set<String> issuers = new HashSet<>(Set.of("CA.Example", "other.test"));
        CAAPolicy policy = new CAAPolicy(issuers);
        issuers.clear();
        assertEquals(Set.of("CA.Example", "other.test"), policy.issuerIdentifiers());
        assertThrows(UnsupportedOperationException.class, () -> policy.issuerIdentifiers().clear());
    }

    @Test
    void rejectsIssuerIdentifiersThatAreNotPlainDomainNames() {
        assertThrows(IllegalArgumentException.class, () -> new CAAPolicy(Set.of()));
        for (String issuer : List.of("", ".", "issuer.test.", "bad_issuer.test", "*.test",
                "https://issuer.test", "bad-.test", "\u00e9.test")) {
            assertThrows(IllegalArgumentException.class, () -> new CAAPolicy(Set.of(issuer)), issuer);
        }
    }

    @Test
    void timeoutLimitsRejectInvalidOrUnrepresentableDurations() {
        Duration valid = Duration.ofSeconds(1);
        Duration maximum = Duration.ofNanos(Long.MAX_VALUE);
        assertEquals(maximum, new CAAPolicy.Limits(maximum, valid, 1, 1, 1).totalTimeout());
        for (Duration invalid : List.of(Duration.ZERO, Duration.ofNanos(-1), maximum.plusNanos(1))) {
            assertThrows(IllegalArgumentException.class, () -> new CAAPolicy.Limits(invalid, valid, 1, 1, 1));
            assertThrows(IllegalArgumentException.class, () -> new CAAPolicy.Limits(valid, invalid, 1, 1, 1));
        }
    }

    @Test
    void evaluationErrorTakesPrecedenceOverPolicyDenialInEitherOrder() {
        Instant now = Instant.now();
        var denied = new CAADecision.NameDecision(new CAARequest.CertificateName(NAME, false),
                CAADecision.Outcome.DENY, CAADecision.Reason.ISSUER_NOT_AUTHORIZED,
                Optional.empty(), List.of(), Optional.empty());
        var failed = new CAADecision.NameDecision(new CAARequest.CertificateName(new DNSDomainName("other.test."), false),
                CAADecision.Outcome.ERROR, CAADecision.Reason.EXPIRED,
                Optional.empty(), List.of(), Optional.empty());
        for (List<CAADecision.NameDecision> names : List.of(List.of(denied, failed), List.of(failed, denied))) {
            assertEquals(CAADecision.Outcome.ERROR,
                    new CAADecision(CAADecision.Outcome.ERROR, names, now, now).outcome());
            assertThrows(IllegalArgumentException.class,
                    () -> new CAADecision(CAADecision.Outcome.DENY, names, now, now));
        }
    }

    @Test
    void normalizesNamesAndRejectsRelativeUnicodeAndMalformedNames() {
        assertEquals(NAME, new DNSDomainName("WWW.EXAMPLE.TEST."));
        for (String invalid : List.of("example.test", "a..test.", "*.test.", "bad-.test.", "\u00e9.test.", "\u212a.test.")) {
            assertThrows(IllegalArgumentException.class, () -> new DNSDomainName(invalid));
        }
        assertThrows(IllegalArgumentException.class, () -> new CAARequest.CertificateName(new DNSDomainName("."), false));
    }

    @Test
    void copiesRequestCollectionsAndRejectsUnrelatedContext() {
        var names = new ArrayList<>(List.of(new CAARequest.CertificateName(NAME, false)));
        var contexts = new HashMap<CAARequest.CertificateName, CAARequest.IssuanceContext>();
        CAARequest request = new CAARequest(names, contexts);
        names.clear();
        contexts.put(new CAARequest.CertificateName(NAME, true), new CAARequest.IssuanceContext(Optional.empty(), Optional.empty()));
        assertEquals(1, request.names().size());
        assertEquals(Map.of(), request.contexts());
        assertThrows(UnsupportedOperationException.class, () -> request.names().clear());
        assertThrows(IllegalArgumentException.class, () -> new CAARequest(request.names(), contexts));
    }

    @Test
    void copiesCaaValueBytesAtBothBoundaries() {
        byte[] input = { 1, 2 };
        CAADNSClient.CAARecord record = new CAADNSClient.CAARecord(NAME, 30, 0, "issue", input);
        input[0] = 3;
        record.value()[1] = 4;
        assertArrayEquals(new byte[] { 1, 2 }, record.value());
    }

    @Test
    void doesNotExposeAdapterSettingsThroughToString() {
        CAADNSClientProvider.Config config = new CAADNSClientProvider.Config(Map.of("secret", "sensitive-value"));
        assertFalse(config.toString().contains("sensitive-value"));
    }

    @Test
    void rejectsUnsupportedAssuranceClaimsAndAcceptsUnclassifiedDelegation() {
        assertThrows(IllegalArgumentException.class,
                () -> evidence(CAADNSClient.DNSSECStatus.SECURE, CAADNSClient.ValidationAssurance.NONE, true));
        assertThrows(IllegalArgumentException.class,
                () -> evidence(CAADNSClient.DNSSECStatus.SECURE, CAADNSClient.ValidationAssurance.TRUSTED_RESOLVER, false));
        assertThrows(IllegalArgumentException.class,
                () -> evidence(CAADNSClient.DNSSECStatus.UNCHECKED, CAADNSClient.ValidationAssurance.TRUSTED_RESOLVER, false));
        assertEquals(CAADNSClient.DNSSECStatus.UNCLASSIFIED,
                evidence(CAADNSClient.DNSSECStatus.UNCLASSIFIED, CAADNSClient.ValidationAssurance.TRUSTED_RESOLVER, false).validationStatus());
    }

    @Test
    void rejectsEmptyPositiveAndAllowsNegativeAnswersWithoutSoa() {
        assertThrows(IllegalArgumentException.class, () -> lookup(NAME, CAADNSClient.LookupKind.RRSET, List.of(), Optional.empty()));
        assertEquals(CAADNSClient.LookupKind.NODATA, lookup(NAME, CAADNSClient.LookupKind.NODATA, List.of(), Optional.empty()).kind());
    }

    @Test
    void rejectsAliasChainsThatDoNotReachTheReportedOwner() {
        DNSDomainName target = new DNSDomainName("target.test.");
        assertThrows(IllegalArgumentException.class,
                () -> lookup(target, CAADNSClient.LookupKind.NODATA, List.of(), Optional.empty()));
        CAADNSClient.AliasStep alias = new CAADNSClient.AliasStep(NAME, target, CAADNSClient.AliasKind.CNAME, 30);
        assertEquals(target, lookup(target, CAADNSClient.LookupKind.NODATA, List.of(alias), Optional.empty()).terminalName());
    }

    @Test
    void rejectsAnAllowAggregateContainingDenial() {
        Instant now = Instant.now();
        CAADecision.NameDecision denied = new CAADecision.NameDecision(new CAARequest.CertificateName(NAME, false), CAADecision.Outcome.DENY,
                CAADecision.Reason.ISSUER_NOT_AUTHORIZED, Optional.empty(), List.of(), Optional.empty());
        assertThrows(IllegalArgumentException.class,
                () -> new CAADecision(CAADecision.Outcome.ALLOW, List.of(denied), now, now.plusSeconds(10)));
    }

    @Test
    void refusesAnAllowDecisionWithoutDiscoveryOrAContradictoryReason() {
        CAARequest.CertificateName name = new CAARequest.CertificateName(NAME, false);
        assertThrows(IllegalArgumentException.class, () -> new CAADecision.NameDecision(name, CAADecision.Outcome.ALLOW,
                CAADecision.Reason.NO_RESTRICTION, Optional.empty(), List.of(), Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new CAADecision.NameDecision(name, CAADecision.Outcome.ERROR,
                CAADecision.Reason.ISSUER_NOT_AUTHORIZED, Optional.empty(), List.of(), Optional.empty()));
    }

    @Test
    void refusesServfailPackagedAsSuccessfulAbsence() {
        var response = new CAADNSClient.ResponseEvidence("fixture", NAME, 2, false, CAADNSClient.DNSSECStatus.UNCHECKED,
                CAADNSClient.ValidationAssurance.NONE, Instant.now(), "fixture", Optional.empty());
        assertThrows(IllegalArgumentException.class, () -> new CAADNSClient.LookupResult(NAME, NAME, CAADNSClient.LookupKind.NODATA,
                List.of(), List.of(), List.of(response), Optional.empty()));
    }

    private static CAADNSClient.ResponseEvidence evidence(CAADNSClient.DNSSECStatus status, CAADNSClient.ValidationAssurance assurance, boolean ad) {
        return new CAADNSClient.ResponseEvidence("fixture", NAME, 0, ad, status, assurance,
                Instant.now(), "fixture", Optional.empty());
    }

    private static CAADNSClient.LookupResult lookup(DNSDomainName terminal, CAADNSClient.LookupKind kind,
            List<CAADNSClient.AliasStep> aliases, Optional<CAADNSClient.SOAEvidence> negative) {
        return new CAADNSClient.LookupResult(NAME, terminal, kind, List.of(), aliases,
                List.of(evidence(CAADNSClient.DNSSECStatus.UNCHECKED, CAADNSClient.ValidationAssurance.NONE, false)), negative);
    }
}

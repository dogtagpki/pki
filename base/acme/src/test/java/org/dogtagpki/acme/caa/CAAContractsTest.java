// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

/**
 * Tests the shared data contracts used to pass certificate names, issuer
 * policy, DNS evidence and decisions through the CAA feature. These checks
 * protect the boundaries between the consuming subsystem, DNS adapter and
 * policy engine: inputs retain their intended meaning, copied data cannot be
 * changed by callers, and contradictory evidence or decisions are rejected.
 * Policy evaluation is covered separately by DefaultCAAValidatorTest.
 */
public class CAAContractsTest {
    private static final DNSDomainName NAME = new DNSDomainName("www.example.test.");

    /**
     * Build a policy from a mutable issuer set, then clear the original set.
     * The policy must retain the supplied spelling and expose an unmodifiable copy.
     */
    @Test
    void validatesIssuerIdentifiersWithoutChangingConfiguredSpelling() {
        Set<String> issuers = new HashSet<>(Set.of("CA.Example", "other.test"));
        CAAPolicy policy = new CAAPolicy(issuers);
        issuers.clear();

        assertEquals(Set.of("CA.Example", "other.test"), policy.issuerIdentifiers());
        assertThrows(UnsupportedOperationException.class, () -> policy.issuerIdentifiers().clear());
    }

    /**
     * Try empty policies and issuer values containing URL, wildcard, Unicode or
     * invalid DNS syntax. Construction must reject them before any DNS lookup.
     */
    @Test
    void rejectsIssuerIdentifiersThatAreNotPlainDomainNames() {
        assertThrows(IllegalArgumentException.class, () -> new CAAPolicy(Set.of()));

        for (String issuer : List.of("", ".", "issuer.test.", "bad_issuer.test", "*.test",
                "https://issuer.test", "bad-.test", "\u00e9.test")) {
            assertThrows(IllegalArgumentException.class, () -> new CAAPolicy(Set.of(issuer)), issuer);
        }
    }

    /**
     * Exercise both timeout fields at their representable nanosecond boundary.
     * Zero, negative and overflowing durations must fail during construction.
     */
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

    /**
     * Combine one denied name with one expired evaluation in both list orders.
     * The aggregate must remain ERROR; ordering must not conceal an unusable check.
     */
    @Test
    void evaluationErrorTakesPrecedenceOverPolicyDenialInEitherOrder() {
        Instant now = Instant.now();
        CAADecision.NameDecision denied = new CAADecision.NameDecision(new CAARequest.CertificateName(NAME, false),
                CAADecision.Outcome.DENY, CAADecision.Reason.ISSUER_NOT_AUTHORIZED,
                Optional.empty(), List.of(), Optional.empty());
        CAARequest.CertificateName otherName = new CAARequest.CertificateName(new DNSDomainName("other.test."), false);
        CAADecision.NameDecision failed = new CAADecision.NameDecision(otherName,
                CAADecision.Outcome.ERROR, CAADecision.Reason.EXPIRED,
                Optional.empty(), List.of(), Optional.empty());

        for (List<CAADecision.NameDecision> names : List.of(List.of(denied, failed), List.of(failed, denied))) {
            assertEquals(CAADecision.Outcome.ERROR,
                    new CAADecision(CAADecision.Outcome.ERROR, names, now, now).outcome());

            assertThrows(IllegalArgumentException.class,
                    () -> new CAADecision(CAADecision.Outcome.DENY, names, now, now));
        }
    }

    /**
     * Compare a mixed-case absolute name with its lowercase form, then supply
     * unsupported inputs. DNS root is valid for discovery but not a certificate name.
     */
    @Test
    void normalizesNamesAndRejectsRelativeUnicodeAndMalformedNames() {
        assertEquals(NAME, new DNSDomainName("WWW.EXAMPLE.TEST."));

        for (String invalid : List.of("example.test", "a..test.", "*.test.", "bad-.test.", "\u00e9.test.", "\u212a.test.")) {
            assertThrows(IllegalArgumentException.class, () -> new DNSDomainName(invalid));
        }
        assertThrows(IllegalArgumentException.class, () -> new CAARequest.CertificateName(new DNSDomainName("."), false));
    }

    /**
     * Accept an internationalized name already converted to ASCII by the
     * consumer. The request preserves its A-label form and ordinary-name status.
     */
    @Test
    void acceptsAsciiIdnCertificateName() {
        DNSDomainName domain = new DNSDomainName("xn--bcher-kva.example.");
        CAARequest.CertificateName name = new CAARequest.CertificateName(domain, false);

        CAARequest request = new CAARequest(List.of(name), Map.of());

        assertEquals("xn--bcher-kva.example.", request.names().get(0).baseName().asciiAbsoluteName());
        assertFalse(request.names().get(0).wildcard());
    }

    /**
     * Mutate the original name/context collections after creating a request.
     * The request must keep its snapshot and reject context for an unrequested name.
     */
    @Test
    void copiesRequestCollectionsAndRejectsUnrelatedContext() {
        List<CAARequest.CertificateName> names = new ArrayList<>(List.of(new CAARequest.CertificateName(NAME, false)));
        Map<CAARequest.CertificateName, CAARequest.IssuanceContext> contexts = new HashMap<>();
        CAARequest request = new CAARequest(names, contexts);
        names.clear();
        CAARequest.CertificateName unrelated = new CAARequest.CertificateName(NAME, true);
        CAARequest.IssuanceContext emptyContext = new CAARequest.IssuanceContext(Optional.empty(), Optional.empty());
        contexts.put(unrelated, emptyContext);

        assertEquals(1, request.names().size());
        assertEquals(Map.of(), request.contexts());
        assertThrows(UnsupportedOperationException.class, () -> request.names().clear());
        assertThrows(IllegalArgumentException.class, () -> new CAARequest(request.names(), contexts));
    }

    /**
     * Modify both the input byte array and an array returned by value().
     * Neither mutation may alter the record, which must own its value bytes.
     */
    @Test
    void copiesCaaValueBytesAtBothBoundaries() {
        byte[] input = { 1, 2 };
        CAADNSClient.CAARecord record = new CAADNSClient.CAARecord(NAME, 30, 0, "issue", input);
        input[0] = 3;
        record.value()[1] = 4;

        assertArrayEquals(new byte[] { 1, 2 }, record.value());
    }

    /**
     * Put a sensitive-looking setting in the provider configuration. Its string
     * representation must omit the value so incidental diagnostics do not expose it.
     */
    @Test
    void doesNotExposeAdapterSettingsThroughToString() {
        CAADNSClientProvider.Config config = new CAADNSClientProvider.Config(Map.of("secret", "sensitive-value"));

        assertFalse(config.toString().contains("sensitive-value"));
    }

    /**
     * A trusted resolver's SECURE classification requires an observed AD flag.
     * Reject a contradictory status instead of constructing misleading evidence.
     */
    @Test
    void rejectsSecureStatusWithoutAuthenticatedData() {
        assertThrows(IllegalArgumentException.class,
                () -> evidence(CAADNSClient.ValidationStatus.SECURE, false));
    }

    /**
     * An AD bit from an untrusted source is only an observation. Recording it
     * must not promote the response into a trusted validation status.
     */
    @Test
    void authenticatedDataDoesNotPromoteUntrustedEvidence() {
        CAADNSClient.ResponseEvidence response = evidence(CAADNSClient.ValidationStatus.UNTRUSTED, true);

        assertTrue(response.authenticatedData());
        assertEquals(CAADNSClient.ValidationStatus.UNTRUSTED, response.validationStatus());
    }

    /**
     * AD-clear trusted delegation is UNCLASSIFIED; it must not claim SECURE.
     */
    @Test
    void acceptsUnclassifiedDelegatedEvidence() {
        CAADNSClient.ResponseEvidence response = evidence(CAADNSClient.ValidationStatus.UNCLASSIFIED, false);

        assertEquals(CAADNSClient.ValidationStatus.UNCLASSIFIED, response.validationStatus());
    }

    /**
     * A positive lookup cannot claim a CAA RRset without any records.
     */
    @Test
    void rejectsEmptyPositiveAnswer() {
        assertThrows(IllegalArgumentException.class,
                () -> lookup(NAME, CAADNSClient.LookupKind.RRSET, List.of(), Optional.empty()));
    }

    /**
     * Established absence may omit optional SOA metadata. This tests the shared
     * result model; the DNS adapter is responsible for establishing absence.
     */
    @Test
    void allowsNegativeAnswerWithoutSoa() {
        CAADNSClient.LookupResult result = lookup(NAME, CAADNSClient.LookupKind.NODATA, List.of(), Optional.empty());
        assertEquals(CAADNSClient.LookupKind.NODATA, result.kind());
    }

    /**
     * Report a terminal name different from the candidate, first without an
     * alias and then with a connecting CNAME step. Only the connected chain is valid.
     */
    @Test
    void rejectsAliasChainsThatDoNotReachTheReportedOwner() {
        DNSDomainName target = new DNSDomainName("target.test.");

        assertThrows(IllegalArgumentException.class,
                () -> lookup(target, CAADNSClient.LookupKind.NODATA, List.of(), Optional.empty()));
        CAADNSClient.AliasStep alias = new CAADNSClient.AliasStep(NAME, target, CAADNSClient.AliasKind.CNAME, 30);

        CAADNSClient.LookupResult result = lookup(target, CAADNSClient.LookupKind.NODATA,
                List.of(alias), Optional.empty());
        assertEquals(target, result.terminalName());
    }

    /**
     * Build an aggregate labelled ALLOW around a denied per-name result.
     * The constructor must reject the contradictory authorization claim.
     */
    @Test
    void rejectsAnAllowAggregateContainingDenial() {
        Instant now = Instant.now();
        CAARequest.CertificateName name = new CAARequest.CertificateName(NAME, false);
        CAADecision.NameDecision denied = new CAADecision.NameDecision(name,
                CAADecision.Outcome.DENY, CAADecision.Reason.ISSUER_NOT_AUTHORIZED, Optional.empty(), List.of(), Optional.empty());

        assertThrows(IllegalArgumentException.class,
                () -> new CAADecision(CAADecision.Outcome.ALLOW, List.of(denied), now, now.plusSeconds(10)));
    }

    /**
     * Try an approval without DNS evidence and an ERROR with a denial reason.
     * Neither inconsistent per-name decision may be constructed.
     */
    @Test
    void refusesAnAllowDecisionWithoutDiscoveryOrAContradictoryReason() {
        CAARequest.CertificateName name = new CAARequest.CertificateName(NAME, false);

        assertThrows(IllegalArgumentException.class, () -> new CAADecision.NameDecision(name, CAADecision.Outcome.ALLOW,
                CAADecision.Reason.NO_RESTRICTION, Optional.empty(), List.of(), Optional.empty()));

        assertThrows(IllegalArgumentException.class, () -> new CAADecision.NameDecision(name, CAADecision.Outcome.ERROR,
                CAADecision.Reason.ISSUER_NOT_AUTHORIZED, Optional.empty(), List.of(), Optional.empty()));
    }

    /**
     * Attach SERVFAIL response evidence to a claimed NODATA lookup.
     * The result constructor must prevent a resolver error from becoming absence.
     */
    @Test
    void refusesServfailPackagedAsSuccessfulAbsence() {
        CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                "fixture", NAME, 2, false, CAADNSClient.ValidationStatus.UNTRUSTED, Instant.now(), "fixture", Optional.empty());

        assertThrows(IllegalArgumentException.class,
                () -> new CAADNSClient.LookupResult(NAME, NAME, CAADNSClient.LookupKind.NODATA,
                        List.of(), List.of(), List.of(response), Optional.empty()));
    }

    private static CAADNSClient.ResponseEvidence evidence(CAADNSClient.ValidationStatus status, boolean ad) {
        return new CAADNSClient.ResponseEvidence("fixture", NAME, 0, ad, status,
                Instant.now(), "fixture", Optional.empty());
    }

    private static CAADNSClient.LookupResult lookup(DNSDomainName terminal, CAADNSClient.LookupKind kind,
            List<CAADNSClient.AliasStep> aliases, Optional<CAADNSClient.SOAEvidence> negative) {
        CAADNSClient.ResponseEvidence response = evidence(CAADNSClient.ValidationStatus.UNCLASSIFIED, false);
        return new CAADNSClient.LookupResult(NAME, terminal, kind,
                List.of(), aliases, List.of(response), negative);
    }
}

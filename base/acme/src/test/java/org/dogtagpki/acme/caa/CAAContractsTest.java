// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
     * Combine one denied name with one DNS failure in both list orders.
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
                CAADecision.Outcome.ERROR, CAADecision.Reason.DNS_FAILURE,
                Optional.empty(), List.of(), Optional.of(new DNSLookupException.Failure(
                        DNSLookupException.Reason.TIMEOUT, "deadline", List.of())));

        for (List<CAADecision.NameDecision> names : List.of(List.of(denied, failed), List.of(failed, denied))) {
            assertEquals(CAADecision.Outcome.ERROR,
                    new CAADecision(CAADecision.Outcome.ERROR, names, now, now, 0L).outcome());

            assertThrows(IllegalArgumentException.class,
                    () -> new CAADecision(CAADecision.Outcome.DENY, names, now, now, 0L));
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
     * A wildcard adds two wire octets to its base. Exercise the exact limit
     * and both larger valid bases while ordinary names retain their full range.
     */
    @Test
    void wildcardLengthIncludesTheWildcardLabel() {
        String prefix = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + ".";
        for (int lastLabelLength : List.of(59, 60, 61)) {
            DNSDomainName base = new DNSDomainName(prefix + "d".repeat(lastLabelLength) + ".");
            assertEquals(193 + lastLabelLength, base.asciiAbsoluteName().length());
            assertEquals(base, new CAARequest.CertificateName(base, false).baseName());

            if (lastLabelLength == 59) {
                assertTrue(new CAARequest.CertificateName(base, true).wildcard());
            } else {
                assertThrows(IllegalArgumentException.class, () -> new CAARequest.CertificateName(base, true),
                        "Wildcard base length " + base.asciiAbsoluteName().length());
            }
        }
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
     * Accept the exact name limit with binding context for every identity,
     * then reject one additional distinct name at the request boundary.
     */
    @Test
    void requestNameLimitAcceptsTheBoundaryAndRejectsAnAdditionalName() {
        List<CAARequest.CertificateName> names = new ArrayList<>();
        Map<CAARequest.CertificateName, CAARequest.IssuanceContext> contexts = new HashMap<>();
        for (int i = 0; i < CAARequest.MAX_NAMES; i++) {
            CAARequest.CertificateName name = new CAARequest.CertificateName(
                    new DNSDomainName("name-" + i + ".example.test."), false);
            names.add(name);
            contexts.put(name, new CAARequest.IssuanceContext(Optional.empty(), Optional.empty()));
        }
        CAARequest request = new CAARequest(names, contexts);
        assertEquals(CAARequest.MAX_NAMES, request.names().size());
        assertEquals(CAARequest.MAX_NAMES, request.contexts().size());

        names.add(new CAARequest.CertificateName(new DNSDomainName("overflow.example.test."), false));
        assertThrows(IllegalArgumentException.class, () -> new CAARequest(names, contexts));
    }

    /**
     * Oversized inputs must be rejected by size before their entries are copied
     * or validated. These fixtures fail immediately if iteration is attempted.
     */
    @Test
    void oversizedRequestCollectionsAreRejectedBeforeCopyingEntries() {
        List<CAARequest.CertificateName> oversized = new AbstractList<>() {
            @Override
            public int size() {
                return CAARequest.MAX_NAMES + 1;
            }

            @Override
            public CAARequest.CertificateName get(int index) {
                throw new AssertionError("Oversized name list was traversed");
            }
        };
        assertThrows(IllegalArgumentException.class, () -> new CAARequest(oversized, Map.of()));

        Map<CAARequest.CertificateName, CAARequest.IssuanceContext> oversizedContexts = new AbstractMap<>() {
            @Override
            public int size() {
                return CAARequest.MAX_NAMES + 1;
            }

            @Override
            public Set<Entry<CAARequest.CertificateName, CAARequest.IssuanceContext>> entrySet() {
                throw new AssertionError("Oversized context map was traversed");
            }
        };
        List<CAARequest.CertificateName> names = List.of(new CAARequest.CertificateName(NAME, false));
        assertThrows(IllegalArgumentException.class, () -> new CAARequest(names, oversizedContexts));
    }

    /**
     * Model a collection changing between size inspection and iteration. The
     * iterator supplies the actual snapshot, including the empty and over-limit
     * cases. A growing source must be rejected by the first excess entry.
     */
    @Test
    void rejectsEmptyOrOversizedSnapshotAfterInitialSizeCheck() {
        for (int actualSize : List.of(0, CAARequest.MAX_NAMES + 2)) {
            List<CAARequest.CertificateName> changing = new AbstractList<>() {
                @Override
                public int size() {
                    return 1;
                }

                @Override
                public Iterator<CAARequest.CertificateName> iterator() {
                    return java.util.stream.IntStream.range(0, actualSize).mapToObj(this::get).iterator();
                }

                @Override
                public CAARequest.CertificateName get(int index) {
                    assertTrue(index <= CAARequest.MAX_NAMES, "Read beyond the first excess name");
                    return new CAARequest.CertificateName(new DNSDomainName("n" + index + ".test."), false);
                }
            };
            assertThrows(IllegalArgumentException.class, () -> new CAARequest(changing, Map.of()),
                    "Actual snapshot size " + actualSize);
        }
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
                () -> new CAADecision(CAADecision.Outcome.ALLOW, List.of(denied), now, now, 0L));
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
     * An issuer grant needs a selected RRset, not merely some DNS observations.
     * Missing/mismatched owners and an RRset before a final absence are invalid.
     */
    @Test
    void issuerAuthorizationRequiresTheSelectedOwnersRrset() {
        CAARequest.CertificateName name = new CAARequest.CertificateName(NAME, false);
        CAADNSClient.LookupResult absence = lookup(NAME, CAADNSClient.LookupKind.NODATA,
                List.of(), Optional.empty());
        CAADNSClient.LookupResult grant = grantLookup(NAME, List.of());

        for (Optional<DNSDomainName> owner : List.of(Optional.<DNSDomainName>empty(), Optional.of(NAME))) {
            assertThrows(IllegalArgumentException.class, () -> new CAADecision.NameDecision(name,
                    CAADecision.Outcome.ALLOW, CAADecision.Reason.ISSUER_AUTHORIZED,
                    owner, List.of(absence), Optional.empty()));
        }
        for (Optional<DNSDomainName> owner : List.of(Optional.<DNSDomainName>empty(),
                Optional.of(new DNSDomainName("other.test.")))) {
            assertThrows(IllegalArgumentException.class, () -> new CAADecision.NameDecision(name,
                    CAADecision.Outcome.ALLOW, CAADecision.Reason.ISSUER_AUTHORIZED,
                    owner, List.of(grant), Optional.empty()));
        }
        assertThrows(IllegalArgumentException.class, () -> new CAADecision.NameDecision(name,
                CAADecision.Outcome.ALLOW, CAADecision.Reason.ISSUER_AUTHORIZED,
                Optional.of(NAME), List.of(grant, absence), Optional.empty()));
    }

    /**
     * Keep legitimate grants at an alias target usable, and continue accepting
     * established absence as NO_RESTRICTION rather than demanding a grant.
     */
    @Test
    void approvalsRetainAliasOwnerAndEstablishedAbsence() {
        CAARequest.CertificateName name = new CAARequest.CertificateName(NAME, false);
        DNSDomainName target = new DNSDomainName("target.test.");
        CAADNSClient.AliasStep alias = new CAADNSClient.AliasStep(NAME, target,
                CAADNSClient.AliasKind.CNAME, 60);
        CAADecision.NameDecision authorized = new CAADecision.NameDecision(name,
                CAADecision.Outcome.ALLOW, CAADecision.Reason.ISSUER_AUTHORIZED,
                Optional.of(target), List.of(grantLookup(target, List.of(alias))), Optional.empty());
        assertEquals(target, authorized.relevantOwner().orElseThrow());

        CAADNSClient.LookupResult absence = lookup(NAME, CAADNSClient.LookupKind.NODATA,
                List.of(), Optional.empty());
        CAADecision.NameDecision unrestricted = new CAADecision.NameDecision(name,
                CAADecision.Outcome.ALLOW, CAADecision.Reason.NO_RESTRICTION,
                Optional.empty(), completeAbsence(), Optional.empty());
        Instant now = Instant.now();
        assertEquals(CAADecision.Outcome.ALLOW, new CAADecision(CAADecision.Outcome.ALLOW,
                List.of(unrestricted), now, now, 0L).outcome());
    }

    /**
     * Reject multiline/control text at the adapter boundary, including Unicode
     * separators that Character.isISOControl() does not identify as controls.
     */
    @Test
    void failureMessagesRejectControlsAndUnicodeLineSeparators() {
        for (String invalid : List.of("line\nbreak", "line\rbreak", "tab\there", "nul\u0000here",
                "next\u0085line", "line\u2028separator", "paragraph\u2029separator", "x".repeat(1025))) {
            assertThrows(IllegalArgumentException.class, () -> new DNSLookupException.Failure(
                    DNSLookupException.Reason.MALFORMED_RESPONSE, invalid, List.of()));
        }
    }

    /** Keep ordinary single-line Unicode and the existing length boundary usable. */
    @Test
    void failureMessagesPreserveSingleLineUnicodeAndMaximumLength() {
        for (String valid : List.of("Resolver: \u00e9chec", "x".repeat(1024))) {
            DNSLookupException.Failure failure = new DNSLookupException.Failure(
                    DNSLookupException.Reason.MALFORMED_RESPONSE, valid, List.of());
            assertEquals(valid, new DNSLookupException(failure).getMessage());
        }
    }

    /**
     * Attach SERVFAIL response evidence to a claimed NODATA lookup.
     * The result constructor must prevent a resolver error from becoming absence.
     */
    @Test
    void refusesServfailPackagedAsSuccessfulAbsence() {
        CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                "fixture", NAME, 2, false, CAADNSClient.ValidationStatus.UNTRUSTED, "fixture", Optional.empty());

        assertThrows(IllegalArgumentException.class,
                () -> new CAADNSClient.LookupResult(NAME, NAME, CAADNSClient.LookupKind.NODATA,
                        List.of(), List.of(), List.of(response), Optional.empty()));
    }

    /** Defensive copies still represent the same record and lookup evidence. */
    @Test
    void caaRecordEqualityUsesAllFieldsAndValueContents() {
        byte[] bytes = "ca.example".getBytes(StandardCharsets.US_ASCII);
        var original = new CAADNSClient.CAARecord(NAME, 60, 0, "issue", bytes);
        var copy = new CAADNSClient.CAARecord(original.owner(), original.ttlSeconds(),
                original.flags(), original.tag(), original.value());
        bytes[0] = 'x';
        copy.value()[0] = 'y';
        assertEquals(original, copy);
        assertEquals(original.hashCode(), copy.hashCode());
        assertEquals(1, new HashSet<>(List.of(original, copy)).size());

        // Each component participates in equality independently.
        for (var changed : List.of(
                new CAADNSClient.CAARecord(new DNSDomainName("other.test."), 60, 0, "issue", original.value()),
                new CAADNSClient.CAARecord(NAME, 61, 0, "issue", original.value()),
                new CAADNSClient.CAARecord(NAME, 60, 128, "issue", original.value()),
                new CAADNSClient.CAARecord(NAME, 60, 0, "issuewild", original.value()),
                new CAADNSClient.CAARecord(NAME, 60, 0, "issue", new byte[] {0}))) {
            assertFalse(original.equals(changed));
        }
        var observation = evidence(CAADNSClient.ValidationStatus.UNCLASSIFIED, false);
        var first = new CAADNSClient.LookupResult(NAME, NAME, CAADNSClient.LookupKind.RRSET,
                List.of(original), List.of(), List.of(observation), Optional.empty());
        var second = new CAADNSClient.LookupResult(NAME, NAME, CAADNSClient.LookupKind.RRSET,
                List.of(copy), List.of(), List.of(observation), Optional.empty());
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
    }

    /** Successful evidence must begin with the requested candidate, including alias lookups. */
    @Test
    void lookupRequiresCandidateQuestionEvidence() {
        DNSDomainName target = new DNSDomainName("target.test.");
        var unrelated = new CAADNSClient.ResponseEvidence("fixture", target, 0, false,
                CAADNSClient.ValidationStatus.UNCLASSIFIED, "fixture", Optional.empty());
        var alias = new CAADNSClient.AliasStep(NAME, target, CAADNSClient.AliasKind.CNAME, 60);
        assertThrows(IllegalArgumentException.class, () -> new CAADNSClient.LookupResult(
                NAME, NAME, CAADNSClient.LookupKind.NODATA, List.of(), List.of(),
                List.of(unrelated), Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new CAADNSClient.LookupResult(
                NAME, target, CAADNSClient.LookupKind.NODATA, List.of(), List.of(alias),
                List.of(unrelated), Optional.empty()));

        // An answer to the candidate can carry the entire alias chain and terminal RRset.
        var grant = grantLookup(target, List.of(alias));
        assertEquals(target, grant.terminalName());
        var multiple = new CAADNSClient.LookupResult(NAME, target, CAADNSClient.LookupKind.RRSET,
                grant.records(), grant.aliases(), List.of(grant.responses().get(0), unrelated), Optional.empty());
        assertEquals(2, multiple.responses().size());
    }

    /** Applicable issuance properties require a policy decision even when their values are empty. */
    @Test
    void noRestrictionRequiresNonrestrictiveSelectedPolicy() {
        for (boolean wildcard : List.of(false, true)) {
            var name = new CAARequest.CertificateName(NAME, wildcard);
            for (String tag : List.of("issue", "ISSUE", "issuewild", "ISSUEWILD", "iodef", "unknown")) {
                var record = new CAADNSClient.CAARecord(NAME, 60, 0, tag,
                        ";".getBytes(StandardCharsets.US_ASCII));
                var lookup = new CAADNSClient.LookupResult(NAME, NAME, CAADNSClient.LookupKind.RRSET,
                        List.of(record), List.of(),
                        List.of(evidence(CAADNSClient.ValidationStatus.UNCLASSIFIED, false)), Optional.empty());
                boolean restricted = tag.equalsIgnoreCase("issue")
                        || wildcard && tag.equalsIgnoreCase("issuewild");
                if (restricted) {
                    assertThrows(IllegalArgumentException.class, () -> new CAADecision.NameDecision(name,
                            CAADecision.Outcome.ALLOW, CAADecision.Reason.NO_RESTRICTION,
                            Optional.of(NAME), List.of(lookup), Optional.empty()), tag);
                } else {
                    var decision = new CAADecision.NameDecision(name, CAADecision.Outcome.ALLOW,
                            CAADecision.Reason.NO_RESTRICTION, Optional.of(NAME), List.of(lookup), Optional.empty());
                    assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
                }
            }
        }
    }

    /** Absence requires every original parent through the TLD; the first RRset ends discovery. */
    @Test
    void approvalsRequireCompleteOrderedDiscovery() {
        var leaf = lookup(NAME, CAADNSClient.LookupKind.NODATA, List.of(), Optional.empty());
        var parent = absence(new DNSDomainName("example.test."));
        var tld = absence(new DNSDomainName("test."));
        var grant = grantLookup(NAME, List.of());
        for (var incomplete : List.of(List.of(leaf), List.of(leaf, tld),
                List.of(parent, tld), List.of(leaf, leaf, parent, tld), List.of(grant, parent))) {
            assertThrows(IllegalArgumentException.class, () -> approved(false, CAADecision.Reason.NO_RESTRICTION,
                    incomplete), incomplete.toString());
        }
        assertEquals(CAADecision.Outcome.ALLOW,
                approved(false, CAADecision.Reason.NO_RESTRICTION, completeAbsence()).outcome());
        assertEquals(CAADecision.Outcome.ALLOW,
                approved(false, CAADecision.Reason.ISSUER_AUTHORIZED, List.of(grant)).outcome());
    }

    /** Unknown critical properties block both approval reasons; recognized reporting properties remain valid. */
    @Test
    void approvalReasonsRejectUnknownCriticalProperties() {
        for (var reason : List.of(CAADecision.Reason.NO_RESTRICTION, CAADecision.Reason.ISSUER_AUTHORIZED)) {
            for (int flags : List.of(0, 1, 128)) {
                var records = new ArrayList<CAADNSClient.CAARecord>();
                records.add(new CAADNSClient.CAARecord(NAME, 60, flags, "UNKNOWN", new byte[0]));
                if (reason == CAADecision.Reason.ISSUER_AUTHORIZED) {
                    records.addAll(grantLookup(NAME, List.of()).records());
                }
                var lookup = rrset(records);
                if (flags == 128) {
                    assertThrows(IllegalArgumentException.class, () -> approved(false, reason, List.of(lookup)));
                } else {
                    assertEquals(CAADecision.Outcome.ALLOW, approved(false, reason, List.of(lookup)).outcome());
                }
            }
        }
        var iodef = new CAADNSClient.CAARecord(NAME, 60, 128, "IODEF", new byte[0]);
        assertEquals(CAADecision.Outcome.ALLOW, approved(false, CAADecision.Reason.NO_RESTRICTION,
                List.of(rrset(List.of(iodef)))).outcome());
    }

    /** issuewild alone applies to a wildcard; ordinary names remain unrestricted by it. */
    @Test
    void issuerAuthorizationRequiresApplicableProperties() {
        var wildcardOnly = rrset(List.of(new CAADNSClient.CAARecord(NAME, 60, 0, "ISSUEWILD", new byte[0])));
        assertThrows(IllegalArgumentException.class, () -> approved(false,
                CAADecision.Reason.ISSUER_AUTHORIZED, List.of(wildcardOnly)));
        assertEquals(CAADecision.Outcome.ALLOW, approved(false, CAADecision.Reason.NO_RESTRICTION,
                List.of(wildcardOnly)).outcome());
        assertEquals(CAADecision.Outcome.ALLOW, approved(true, CAADecision.Reason.ISSUER_AUTHORIZED,
                List.of(wildcardOnly)).outcome());
        var reportingOnly = rrset(List.of(new CAADNSClient.CAARecord(NAME, 60, 0, "iodef", new byte[0])));
        assertThrows(IllegalArgumentException.class, () -> approved(true,
                CAADecision.Reason.ISSUER_AUTHORIZED, List.of(reportingOnly)));
    }

    /** An AD bit cannot repair untrusted leaf, parent, or alias observations in an approval. */
    @Test
    void approvalsRequireTrustedEvidenceAcrossAllDiscovery() {
        var trusted = evidence(CAADNSClient.ValidationStatus.UNCLASSIFIED, false);
        var untrusted = evidence(CAADNSClient.ValidationStatus.UNTRUSTED, true);
        var grant = grantLookup(NAME, List.of());
        for (var responses : List.of(List.of(untrusted), List.of(untrusted, trusted), List.of(trusted, untrusted))) {
            var result = new CAADNSClient.LookupResult(NAME, NAME, CAADNSClient.LookupKind.RRSET,
                    grant.records(), List.of(), responses, Optional.empty());
            assertThrows(IllegalArgumentException.class,
                    () -> approved(false, CAADecision.Reason.ISSUER_AUTHORIZED, List.of(result)));
        }
        // A trusted leaf cannot hide an untrusted parent or TLD absence.
        for (int position = 0; position < completeAbsence().size(); position++) {
            var discovery = new ArrayList<>(completeAbsence());
            var original = discovery.get(position);
            var badResponse = new CAADNSClient.ResponseEvidence("fixture", original.candidate(), 0, true,
                    CAADNSClient.ValidationStatus.UNTRUSTED, "fixture", Optional.empty());
            discovery.set(position, new CAADNSClient.LookupResult(original.candidate(), original.terminalName(),
                    original.kind(), List.of(), List.of(), List.of(badResponse), Optional.empty()));
            assertThrows(IllegalArgumentException.class,
                    () -> approved(false, CAADecision.Reason.NO_RESTRICTION, discovery));
        }
        DNSDomainName target = new DNSDomainName("target.test.");
        var alias = new CAADNSClient.AliasStep(NAME, target, CAADNSClient.AliasKind.CNAME, 60);
        var aliased = grantLookup(target, List.of(alias));
        var untrustedTarget = new CAADNSClient.ResponseEvidence("fixture", target, 0, true,
                CAADNSClient.ValidationStatus.UNTRUSTED, "fixture", Optional.empty());
        var aliasLookup = new CAADNSClient.LookupResult(NAME, target, CAADNSClient.LookupKind.RRSET,
                aliased.records(), List.of(alias), List.of(trusted, untrustedTarget), Optional.empty());
        Instant now = Instant.now();
        assertThrows(IllegalArgumentException.class, () -> new CAADecision(CAADecision.Outcome.ALLOW,
                List.of(approved(false, CAADecision.Reason.ISSUER_AUTHORIZED, List.of(aliasLookup))), now, now, 0));
        var failed = new CAADecision.NameDecision(new CAARequest.CertificateName(NAME, false),
                CAADecision.Outcome.ERROR, CAADecision.Reason.DNS_FAILURE, Optional.empty(), List.of(),
                Optional.of(new DNSLookupException.Failure(DNSLookupException.Reason.VALIDATION_FAILURE,
                        "untrusted response", List.of(untrusted))));
        assertEquals(List.of(untrusted), failed.failure().orElseThrow().partialResponses());
    }

    /** A matching first question cannot make an unrelated later response establish absence. */
    @Test
    void everyResponseQuestionMustBelongToTheAliasChain() {
        var first = evidence(CAADNSClient.ValidationStatus.UNCLASSIFIED, false);
        var unrelated = new DNSDomainName("unrelated.test.");
        for (int rcode : List.of(0, 3)) {
            var last = new CAADNSClient.ResponseEvidence("fixture", unrelated, rcode, false,
                    CAADNSClient.ValidationStatus.UNCLASSIFIED, "fixture", Optional.empty());
            var kind = rcode == 3 ? CAADNSClient.LookupKind.NXDOMAIN : CAADNSClient.LookupKind.NODATA;
            assertThrows(IllegalArgumentException.class, () -> new CAADNSClient.LookupResult(NAME, NAME,
                    kind, List.of(), List.of(), List.of(first, last), Optional.empty()));
        }
        // A single response to the candidate can contain the entire alias chain.
        var alias = new CAADNSClient.AliasStep(NAME, unrelated, CAADNSClient.AliasKind.CNAME, 60);
        var single = new CAADNSClient.LookupResult(NAME, unrelated, CAADNSClient.LookupKind.NODATA,
                List.of(), List.of(alias), List.of(first), Optional.empty());
        assertEquals(unrelated, single.terminalName());
    }

    private static CAADecision.NameDecision approved(boolean wildcard, CAADecision.Reason reason,
            List<CAADNSClient.LookupResult> discovery) {
        var last = discovery.get(discovery.size() - 1);
        var owner = last.kind() == CAADNSClient.LookupKind.RRSET
                ? Optional.of(last.terminalName()) : Optional.<DNSDomainName>empty();
        return new CAADecision.NameDecision(new CAARequest.CertificateName(NAME, wildcard),
                CAADecision.Outcome.ALLOW, reason, owner, discovery, Optional.empty());
    }

    private static CAADNSClient.LookupResult rrset(List<CAADNSClient.CAARecord> records) {
        return new CAADNSClient.LookupResult(NAME, NAME, CAADNSClient.LookupKind.RRSET,
                records, List.of(), List.of(evidence(CAADNSClient.ValidationStatus.UNCLASSIFIED, false)), Optional.empty());
    }

    private static CAADNSClient.LookupResult absence(DNSDomainName name) {
        var response = new CAADNSClient.ResponseEvidence("fixture", name, 0, false,
                CAADNSClient.ValidationStatus.UNCLASSIFIED, "fixture", Optional.empty());
        return new CAADNSClient.LookupResult(name, name, CAADNSClient.LookupKind.NODATA,
                List.of(), List.of(), List.of(response), Optional.empty());
    }

    private static List<CAADNSClient.LookupResult> completeAbsence() {
        return List.of(absence(NAME), absence(new DNSDomainName("example.test.")), absence(new DNSDomainName("test.")));
    }

    private static CAADNSClient.ResponseEvidence evidence(CAADNSClient.ValidationStatus status, boolean ad) {
        return new CAADNSClient.ResponseEvidence("fixture", NAME, 0, ad, status,
                "fixture", Optional.empty());
    }

    private static CAADNSClient.LookupResult grantLookup(DNSDomainName terminal,
            List<CAADNSClient.AliasStep> aliases) {
        CAADNSClient.CAARecord record = new CAADNSClient.CAARecord(terminal, 60, 0, "issue",
                "ca.example".getBytes(StandardCharsets.US_ASCII));
        return new CAADNSClient.LookupResult(NAME, terminal, CAADNSClient.LookupKind.RRSET,
                List.of(record), aliases,
                List.of(evidence(CAADNSClient.ValidationStatus.UNCLASSIFIED, false)), Optional.empty());
    }

    private static CAADNSClient.LookupResult lookup(DNSDomainName terminal, CAADNSClient.LookupKind kind,
            List<CAADNSClient.AliasStep> aliases, Optional<CAADNSClient.SOAEvidence> negative) {
        CAADNSClient.ResponseEvidence response = evidence(CAADNSClient.ValidationStatus.UNCLASSIFIED, false);
        return new CAADNSClient.LookupResult(NAME, terminal, kind,
                List.of(), aliases, List.of(response), negative);
    }
}

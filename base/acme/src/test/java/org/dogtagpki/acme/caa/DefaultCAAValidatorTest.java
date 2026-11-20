// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * Tests how the shared engine turns certificate names, trusted issuance
 * context and DNS results into CAA authorization decisions. In-memory DNS
 * answers exercise discovery and policy together, independently of any DNS
 * library or enrollment protocol. The suite also covers attempt-wide resource
 * limits and validator shutdown. DNSSEC cases check the provider-assurance
 * contract using fabricated trusted evidence; signature validation and DNS
 * transport belong to adapter tests.
 */
class DefaultCAAValidatorTest {
    private static final String ISSUER = "ca.example";
    private static final CAARequest.CertificateName NAME = name("www.customer.test", false);

    /**
     * Leave the DNS fixture empty so every candidate returns NODATA. Verify
     * allowance after querying leaf, parent and TLD, with no query for the DNS root.
     */
    @Test
    void climbsOriginalParentsIncludingTldAndExcludesRoot() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAARequest certificateRequest = request(NAME);

            CAADecision allowed = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
            assertEquals(List.of("www.customer.test.", "customer.test.", "test."), client.queries);
        }
    }

    /**
     * Model an alias to edge.hosting.test with no CAA, and grant at customer.test.
     * The query log must show the original parent, never the alias target parent.
     */
    @Test
    void aliasAbsenceClimbsOriginalParentRatherThanAliasParent() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            DNSDomainName candidate = NAME.baseName();
            DNSDomainName target = domain("edge.hosting.test");
            CAADNSClient.AliasStep alias = new CAADNSClient.AliasStep(
                    candidate, target, CAADNSClient.AliasKind.CNAME, 60);
            CAADNSClient.ResponseEvidence response = evidence(candidate);
            CAADNSClient.LookupResult lookup = new CAADNSClient.LookupResult(
                    candidate, target, CAADNSClient.LookupKind.NODATA,
                    List.of(), List.of(alias), List.of(response), Optional.empty());
            client.answers.put(candidate, lookup);
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER));
            CAARequest certificateRequest = request(NAME);

            CAADecision allowed = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
            assertEquals(List.of("www.customer.test.", "customer.test."), client.queries);
        }
    }

    /**
     * Place reporting-only CAA at the leaf and a deny-all policy at its parent.
     * The leaf RRset must stop discovery without applying the parent restriction.
     */
    @Test
    void iodefOnlyStopsSearchWithoutRestrictingIssuers() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "iodef", "mailto:security@example.com"));
            client.put("customer.test", record("customer.test", 0, "issue", ";"));
            CAARequest certificateRequest = request(NAME);

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
            assertEquals(CAADecision.Reason.NO_RESTRICTION, decision.names().get(0).reason());
            assertEquals(1, client.queries.size());
        }
    }

    /**
     * Critical iodef is still a recognized reporting property. It must not
     * require report dispatch or change the authorization of an issue grant.
     */
    @Test
    void criticalIodefDoesNotRequireReportDispatch() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAADNSClient.CAARecord reporting = record("www.customer.test", 128,
                "iodef", "mailto:security@example.com");

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", reporting);

            CAADecision unrestricted = validator.validate(request(NAME));

            assertEquals(CAADecision.Outcome.ALLOW, unrestricted.outcome());
            assertEquals(CAADecision.Reason.NO_RESTRICTION, unrestricted.names().get(0).reason());

            client.put("www.customer.test", reporting, record("www.customer.test", 0, "issue", ISSUER));

            CAADecision allowed = validator.validate(request(NAME));

            assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
            assertEquals(CAADecision.Reason.ISSUER_AUTHORIZED, allowed.names().get(0).reason());

            client.put("www.customer.test", reporting, record("www.customer.test", 0, "issue", ";"));

            CAADecision denied = validator.validate(request(NAME));

            assertEquals(CAADecision.Outcome.DENY, denied.outcome());
            assertEquals(CAADecision.Reason.ISSUER_NOT_AUTHORIZED, denied.names().get(0).reason());
        }
    }

    /**
     * Combine each non-granting issue value with a valid issuer grant.
     * The valid record must still allow issuance; grants are additive.
     */
    @Test
    void emptyAndMalformedIssueDoNotOverrideAnotherGrant() throws Exception {
        for (String value : List.of(";", "", "%%%%%", ISSUER + "; malformed")) {
            InMemoryDNSClient client = new InMemoryDNSClient();

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                client.put("www.customer.test", record("www.customer.test", 0, "issue", value),
                        record("www.customer.test", 0, "issue", ISSUER.toUpperCase()));
                CAARequest certificateRequest = request(NAME);

                CAADecision allowed = validator.validate(certificateRequest);

                assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
            }
        }
    }

    /**
     * Return each malformed or empty issuer value as the only issue record.
     * Without another passing grant, the name must be denied.
     */
    @Test
    void malformedIssueAloneDoesNotGrant() throws Exception {
        for (String value : List.of(";", "%%%%%", ISSUER + "; malformed", ISSUER + ";x=a b")) {
            InMemoryDNSClient client = new InMemoryDNSClient();

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                client.put("www.customer.test", record("www.customer.test", 0, "issue", value));
                CAARequest certificateRequest = request(NAME);

                CAADecision denied = validator.validate(certificateRequest);

                assertEquals(CAADecision.Outcome.DENY, denied.outcome());
            }
        }
    }

    /**
     * Request an ordinary and wildcard name with the same base. One DNS lookup
     * must support separate decisions: issue allows the ordinary name, issuewild denies.
     */
    @Test
    void wildcardPrecedenceAndSameAttemptLookupSharing() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER),
                    record("www.customer.test", 0, "issuewild", ";"));
            CAARequest certificateRequest = request(NAME, name("www.customer.test", true));

            CAADecision result = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, result.names().get(0).outcome());
            assertEquals(CAADecision.Outcome.DENY, result.names().get(1).outcome());
            assertEquals(1, client.queries.size());
        }
    }

    /**
     * Reserved flag 1 must not turn an unknown property into a restriction.
     */
    @Test
    void reservedFlagDoesNotMakeAnUnknownPropertyCritical() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 1, "future", "opaque"));
        CAARequest request = request(NAME);

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
        }
    }

    /**
     * Critical flag 128 must deny an unknown property even without issue records.
     */
    @Test
    void criticalFlagBlocksAnUnknownProperty() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 128, "future", "opaque"));
        CAARequest request = request(NAME);

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.DENY, decision.outcome());
            assertEquals(CAADecision.Reason.UNKNOWN_CRITICAL_PROPERTY, decision.names().get(0).reason());
        }
    }

    /**
     * Matching trusted account and method facts satisfy both binding parameters.
     */
    @Test
    void matchingAccountAndMethodSatisfyBinding() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issue",
                ISSUER + ";accounturi=https://acme.example/acct/1;validationmethods=dns-01,http-01"));
        CAARequest request = requestWithContext("https://acme.example/acct/1", "dns-01");

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
        }
    }

    /**
     * A grant requiring account and method facts must not pass without context.
     */
    @Test
    void missingContextCannotSatisfyBinding() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issue",
                ISSUER + ";accounturi=https://acme.example/acct/1;validationmethods=dns-01,http-01"));
        CAARequest request = request(NAME);

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.DENY, decision.outcome());
            assertEquals(CAADecision.Reason.MISSING_BINDING_CONTEXT, decision.names().get(0).reason());
        }
    }

    /**
     * Account URI comparison preserves the supplied string. A URI with a
     * differently cased host must not match, even when the method is correct.
     */
    @Test
    void accountBindingUsesExactStringComparison() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue",
                    ISSUER + ";accounturi=https://acme.example/acct/1"));
            CAARequest certificateRequest = requestWithContext("https://acme.example/acct/1", "dns-01");

            CAADecision matching = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, matching.outcome());

            CAARequest differentAccountRequest = requestWithContext("https://ACME.example/acct/1", "dns-01");

            CAADecision differentCase = validator.validate(differentAccountRequest);

            assertEquals(CAADecision.Outcome.DENY, differentCase.outcome());
            assertEquals(CAADecision.Reason.ACCOUNT_NOT_AUTHORIZED, differentCase.names().get(0).reason());
        }
    }

    /**
     * Isolate method binding from account binding. An allowed method must pass;
     * another successful challenge method must not satisfy this grant.
     */
    @Test
    void methodBindingRequiresTheMethodUsedForThisName() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue",
                    ISSUER + ";validationmethods=dns-01"));
            CAARequest certificateRequest = requestWithContext("https://acme.example/acct/1", "dns-01");

            CAADecision matching = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, matching.outcome());

            CAARequest differentMethodRequest = requestWithContext("https://acme.example/acct/1", "http-01");

            CAADecision wrongMethod = validator.validate(differentMethodRequest);

            assertEquals(CAADecision.Outcome.DENY, wrongMethod.outcome());
            assertEquals(CAADecision.Reason.VALIDATION_METHOD_NOT_AUTHORIZED, wrongMethod.names().get(0).reason());
        }
    }

    /**
     * Supply complete, matching account/method context so only the unsupported
     * or duplicate parameter can explain rejection. Check the specific reason.
     */
    @Test
    void unsupportedAndDuplicateParametersRejectAnOtherwiseMatchingGrant() throws Exception {
        CAARequest boundRequest = requestWithContext("https://acme.example/acct/1", "dns-01");
        List<String> parameters = List.of(
                "unknown=value",
                "accounturi=https://acme.example/acct/1;accounturi=https://acme.example/acct/1",
                "validationmethods=dns-01;validationmethods=dns-01");

        for (String parameter : parameters) {
            InMemoryDNSClient client = new InMemoryDNSClient();

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER + ";" + parameter));

                CAADecision decision = validator.validate(boundRequest);

                assertEquals(CAADecision.Outcome.DENY, decision.outcome(), parameter);
                assertEquals(CAADecision.Reason.UNSUPPORTED_PARAMETERS, decision.names().get(0).reason(), parameter);
                // An unusable grant must not cancel a separate matching grant.
                client.put("www.customer.test",
                        record("www.customer.test", 0, "issue", ISSUER + ";" + parameter),
                        record("www.customer.test", 0, "issue", ISSUER));

                CAADecision allowed = validator.validate(boundRequest);

                assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome(), parameter);
            }
        }
    }

    /**
     * An empty method list grants nothing even with otherwise valid context.
     */
    @Test
    void emptyValidationMethodListDoesNotGrant() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER + ";validationmethods="));
            CAARequest certificateRequest = requestWithContext("https://acme.example/acct/1", "dns-01");

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.DENY, decision.outcome());
            assertEquals(CAADecision.Reason.VALIDATION_METHOD_NOT_AUTHORIZED, decision.names().get(0).reason());
        }
    }

    /**
     * Make the first fixture lookup throw a resolver failure. Expect ERROR and
     * only one query, rather than parent traversal that could find a permissive policy.
     */
    @Test
    void lookupErrorsStopDiscoveryAndNeverBecomeAbsence() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.error = true;
            CAARequest certificateRequest = request(NAME);

            CAADecision result = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ERROR, result.outcome());
            assertEquals(1, client.queries.size());
        }
    }

    /**
     * An untrusted unrestricted grant could have had its binding parameters
     * stripped in transit. Reject its evidence before evaluating that grant.
     */
    @Test
    void untrustedUnrestrictedGrantCannotAuthorizeIssuance() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAADNSClient.LookupResult untrusted = new CAADNSClient.LookupResult(
                NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                List.of(record("www.customer.test", 0, "issue", ISSUER)), List.of(),
                List.of(untrustedEvidence(NAME.baseName())), Optional.empty());
        client.answers.put(NAME.baseName(), untrusted);
        CAARequest request = requestWithContext("https://acme.example/acct/B", "dns-01");

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                    decision.names().get(0).failure().orElseThrow().reason());
            assertEquals(List.of("www.customer.test."), client.queries);
        }
    }

    /**
     * An untrusted DNS source can set AD on an unrestricted issuer grant.
     * The engine must reject that grant regardless of the observed AD flag.
     */
    @Test
    void authenticatedDataCannotMakeAnUntrustedGrantAuthorizeIssuance() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                "fixture", NAME.baseName(), 0, true, CAADNSClient.ValidationStatus.UNTRUSTED,
                Instant.now(), "fixture", Optional.empty());
        CAADNSClient.LookupResult untrusted = new CAADNSClient.LookupResult(
                NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                List.of(record("www.customer.test", 0, "issue", ISSUER)), List.of(),
                List.of(response), Optional.empty());
        client.answers.put(NAME.baseName(), untrusted);
        CAARequest request = requestWithContext("https://acme.example/acct/B", "dns-01");

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                    decision.names().get(0).failure().orElseThrow().reason());
            assertEquals(List.of("www.customer.test."), client.queries);
        }
    }

    /**
     * An untrusted absence result could hide the entire CAA RRset. NODATA and
     * NXDOMAIN must both fail before parent discovery can find a permissive grant.
     */
    @Test
    void untrustedAbsenceCannotAuthorizeIssuance() throws Exception {
        for (CAADNSClient.LookupKind kind : List.of(CAADNSClient.LookupKind.NODATA, CAADNSClient.LookupKind.NXDOMAIN)) {
            InMemoryDNSClient client = new InMemoryDNSClient();
            int rcode = kind == CAADNSClient.LookupKind.NXDOMAIN ? 3 : 0;
            CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                    "fixture", NAME.baseName(), rcode, false, CAADNSClient.ValidationStatus.UNTRUSTED, Instant.now(), "fixture", Optional.empty());
            CAADNSClient.LookupResult untrusted = new CAADNSClient.LookupResult(
                    NAME.baseName(), NAME.baseName(), kind,
                    List.of(), List.of(), List.of(response), Optional.empty());
            client.answers.put(NAME.baseName(), untrusted);
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER));
            CAARequest request = request(NAME);

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                CAADecision decision = validator.validate(request);

                assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
                assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                        decision.names().get(0).failure().orElseThrow().reason());
                assertEquals(List.of("www.customer.test."), client.queries);
            }
        }
    }

    /**
     * A wildcard uses issue when the RRset has no issuewild property.
     */
    @Test
    void wildcardFallsBackToIssue() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        CAARequest request = request(name("www.customer.test", true));

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
        }
    }

    /**
     * An issuewild restriction does not apply to an ordinary certificate name.
     */
    @Test
    void issuewildDoesNotRestrictOrdinaryNames() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issuewild", ";"));
        CAARequest request = request(NAME);

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
        }
    }

    /**
     * An issuewild deny-all property blocks a wildcard certificate name.
     */
    @Test
    void issuewildCanDenyWildcardNames() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issuewild", ";"));
        CAARequest request = request(name("www.customer.test", true));

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.DENY, decision.outcome());
        }
    }

    /**
     * Combine a valid issue grant with an unknown property using critical flag
     * 128 plus a reserved bit. Critical handling must deny the entire RRset.
     */
    @Test
    void unknownCriticalPropertyOverridesAnOtherwiseValidGrant() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER),
                    record("www.customer.test", 129, "future", "opaque"));
            CAARequest certificateRequest = request(NAME);

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.DENY, decision.outcome());
            assertEquals(CAADecision.Reason.UNKNOWN_CRITICAL_PROPERTY, decision.names().get(0).reason());
        }
    }

    /**
     * Grant one requested name and deny the other. Preserve both per-name
     * outcomes and return aggregate DENY, with both names present in the query log.
     */
    @Test
    void everyRequestedNameIsCheckedAndOneDenialBlocksTheAggregate() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
            client.put("api.customer.test", record("api.customer.test", 0, "issue", "other.test"));
            CAARequest certificateRequest = request(NAME, name("api.customer.test", false));

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.DENY, decision.outcome());
            assertEquals(2, decision.names().size());
            assertEquals(CAADecision.Outcome.ALLOW, decision.names().get(0).outcome());
            assertEquals(CAADecision.Outcome.DENY, decision.names().get(1).outcome());
            assertEquals(List.of("www.customer.test.", "api.customer.test."), client.queries);
        }
    }

    /**
     * Give sibling names a common parent grant. Reuse the parent lookup within
     * the attempt while retaining a separate successful decision for each name.
     */
    @Test
    void siblingNamesShareParentDiscoveryButRetainSeparateDecisions() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER));
            CAARequest certificateRequest = request(NAME, name("api.customer.test", false));

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
            assertEquals(2, decision.names().size());
            assertEquals(List.of("www.customer.test.", "customer.test.", "api.customer.test."), client.queries);

            for (CAADecision.NameDecision nameDecision : decision.names()) {
                assertEquals(CAADecision.Outcome.ALLOW, nameDecision.outcome());
                assertEquals(domain("customer.test"), nameDecision.relevantOwner().orElseThrow());
            }
        }
    }

    /**
     * Reuse a parent grant requiring dns-01 for siblings with different methods.
     * The dns-01 name must allow and the http-01 name must deny despite shared DNS data.
     */
    @Test
    void sharedParentPolicyUsesEachNamesOwnBindingContext() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER + ";validationmethods=dns-01"));
            CAARequest.CertificateName other = name("api.customer.test", false);
            CAARequest.IssuanceContext dnsContext = new CAARequest.IssuanceContext(
                    Optional.empty(), Optional.of("dns-01"));
            CAARequest.IssuanceContext httpContext = new CAARequest.IssuanceContext(
                    Optional.empty(), Optional.of("http-01"));
            CAARequest request = new CAARequest(List.of(NAME, other), Map.of(NAME, dnsContext, other, httpContext));

            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.ALLOW, decision.names().get(0).outcome());
            assertEquals(CAADecision.Outcome.DENY, decision.names().get(1).outcome());
            assertEquals(List.of("www.customer.test.", "customer.test.", "api.customer.test."), client.queries);
        }
    }

    /**
     * Return fresh leaf absence followed by a nine-hour-old parent grant with
     * a long TTL. The oldest observation must expire the decision despite that TTL.
     */
    @Test
    void staleParentEvidenceCannotBeHiddenByAFreshLeafResponse() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            DNSDomainName parent = domain("customer.test");
            CAADNSClient.ResponseEvidence stale = new CAADNSClient.ResponseEvidence("fixture", parent, 0, false,
                    CAADNSClient.ValidationStatus.UNCLASSIFIED,
                    Instant.now().minusSeconds(9 * 3600), "fixture", Optional.empty());
            CAADNSClient.CAARecord grant = new CAADNSClient.CAARecord(
                    parent, 100000, 0, "issue", ISSUER.getBytes(StandardCharsets.US_ASCII));
            CAADNSClient.LookupResult lookup = new CAADNSClient.LookupResult(
                    parent, parent, CAADNSClient.LookupKind.RRSET,
                    List.of(grant), List.of(), List.of(stale), Optional.empty());
            client.answers.put(parent, lookup);
            CAARequest certificateRequest = request(NAME);

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            assertEquals(CAADecision.Reason.EXPIRED, decision.names().get(0).reason());
        }
    }

    /**
     * Model a response timestamp ahead of validation completion. The approval
     * must expire within the configured maximum age measured from completion.
     */
    @Test
    void futureObservationCannotExtendDecisionAgeBeyondCompletion() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAADNSClient.ResponseEvidence future = new CAADNSClient.ResponseEvidence(
                "fixture", NAME.baseName(), 0, false, CAADNSClient.ValidationStatus.UNCLASSIFIED,
                Instant.now().plusSeconds(600), "fixture", Optional.empty());
        CAADNSClient.LookupResult lookup = new CAADNSClient.LookupResult(
                NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                List.of(record("www.customer.test", 0, "issue", ISSUER)),
                List.of(), List.of(future), Optional.empty());
        client.answers.put(NAME.baseName(), lookup);

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request(NAME));

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
            assertEquals(decision.checkedAt().plus(policy().maxDecisionAge()), decision.expiresAt());
        }
    }

    /**
     * Expire a passing grant in an attempt that also contains a policy denial
     * and a failed lookup. Only the approval changes to EXPIRED. Operators
     * must retain the selected owners, discovery records and typed DNS failure.
     */
    @Test
    void expiryPreservesDenialsDnsFailuresAndDiscovery() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAARequest.CertificateName deniedName = name("denied.customer.test", false);
        CAARequest.CertificateName failedName = name("failed.customer.test", false);
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        client.put("denied.customer.test", record("denied.customer.test", 0, "issue", ";"));

        // Old evidence expires the attempt without waiting or changing the
        // test machine's clock. Both names retain their original DNS records.
        CAADNSClient.LookupResult freshGrant = client.answers.get(NAME.baseName());
        CAADNSClient.ResponseEvidence stale = new CAADNSClient.ResponseEvidence(
                "fixture", NAME.baseName(), 0, false, CAADNSClient.ValidationStatus.UNCLASSIFIED,
                Instant.now().minusSeconds(9 * 3600), "fixture", Optional.empty());
        CAADNSClient.LookupResult staleGrant = new CAADNSClient.LookupResult(
                NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                freshGrant.records(), List.of(), List.of(stale), Optional.empty());
        client.answers.put(NAME.baseName(), staleGrant);
        CAADNSClient.LookupResult denial = client.answers.get(deniedName.baseName());
        client.onLookup = () -> {
            String candidate = client.queries.get(client.queries.size() - 1);
            client.error = candidate.equals(failedName.baseName().asciiAbsoluteName());
        };

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request(NAME, deniedName, failedName));

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            CAADecision.NameDecision expired = decision.names().get(0);
            assertEquals(CAADecision.Outcome.ERROR, expired.outcome());
            assertEquals(CAADecision.Reason.EXPIRED, expired.reason());
            assertEquals(Optional.of(NAME.baseName()), expired.relevantOwner());
            assertEquals(List.of(staleGrant), expired.discovery());

            CAADecision.NameDecision denied = decision.names().get(1);
            assertEquals(CAADecision.Outcome.DENY, denied.outcome());
            assertEquals(CAADecision.Reason.ISSUER_NOT_AUTHORIZED, denied.reason());
            assertEquals(Optional.of(deniedName.baseName()), denied.relevantOwner());
            assertEquals(List.of(denial), denied.discovery());

            CAADecision.NameDecision failed = decision.names().get(2);
            assertEquals(CAADecision.Outcome.ERROR, failed.outcome());
            assertEquals(CAADecision.Reason.DNS_FAILURE, failed.reason());
            assertEquals(DNSLookupException.Reason.RCODE_FAILURE, failed.failure().orElseThrow().reason());
        }
    }

    /**
     * A stale denial remains a policy denial when no name was approved. This
     * also checks aggregate recomputation after expiry preserves an all-DENY result.
     */
    @Test
    void expiryDoesNotReplaceAnExistingPolicyDenial() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAADNSClient.ResponseEvidence stale = new CAADNSClient.ResponseEvidence(
                "fixture", NAME.baseName(), 0, false, CAADNSClient.ValidationStatus.UNCLASSIFIED,
                Instant.now().minusSeconds(9 * 3600), "fixture", Optional.empty());
        CAADNSClient.LookupResult lookup = new CAADNSClient.LookupResult(
                NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                List.of(record("www.customer.test", 0, "issue", ";")),
                List.of(), List.of(stale), Optional.empty());
        client.answers.put(NAME.baseName(), lookup);

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request(NAME));

            assertEquals(CAADecision.Outcome.DENY, decision.outcome());
            assertEquals(CAADecision.Outcome.DENY, decision.names().get(0).outcome());
            assertEquals(CAADecision.Reason.ISSUER_NOT_AUTHORIZED, decision.names().get(0).reason());
            assertEquals(Optional.of(NAME.baseName()), decision.names().get(0).relevantOwner());
            assertEquals(List.of(lookup), decision.names().get(0).discovery());
        }
    }

    /**
     * Return an authorized RRset with both untrusted and secure observations
     * from a delegated provider. A secure final observation cannot repair earlier gaps.
     */
    @Test
    void secureFinalAnswerCannotCoverAnUnvalidatedEarlierObservation() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADNSClient.ResponseEvidence secure = new CAADNSClient.ResponseEvidence("fixture", NAME.baseName(), 0, true,
                    CAADNSClient.ValidationStatus.SECURE,
                    Instant.now(), "fixture", Optional.empty());
            CAADNSClient.CAARecord grant = record("www.customer.test", 0, "issue", ISSUER);
            CAADNSClient.ResponseEvidence untrusted = untrustedEvidence(NAME.baseName());
            CAADNSClient.LookupResult lookup = new CAADNSClient.LookupResult(
                    NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                    List.of(grant), List.of(), List.of(untrusted, secure), Optional.empty());
            client.answers.put(NAME.baseName(), lookup);
            CAARequest certificateRequest = request(NAME);

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE, decision.names().get(0).failure().orElseThrow().reason());
        }
    }

    /**
     * Append control or non-ASCII bytes to an otherwise matching issuer value.
     * Those bytes must make the grant unusable rather than being discarded.
     */
    @Test
    void controlAndNonAsciiIssueBytesNeverGrantAuthorization() throws Exception {
        for (byte value : new byte[] {0, 10, 13, (byte) 255}) {
            InMemoryDNSClient client = new InMemoryDNSClient();

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                byte[] bytes = (ISSUER + "x").getBytes(StandardCharsets.US_ASCII);
                bytes[bytes.length - 1] = value;
                client.put("www.customer.test", new CAADNSClient.CAARecord(NAME.baseName(), 60, 0, "issue", bytes));
                CAARequest certificateRequest = request(NAME);

                CAADecision denied = validator.validate(certificateRequest);

                assertEquals(CAADecision.Outcome.DENY, denied.outcome());
            }
        }
    }

    /**
     * Block enough concurrent lookups to occupy every validator slot. An extra
     * attempt must fail without DNS; after releasing the blocked calls, admission recovers.
     */
    @Test
    void saturationRejectsWithoutDnsAndAdmissionRecoversAfterCompletion() throws Exception {
        CAAPolicy policy = policy();
        // Each worker decrements entered after reaching the DNS fixture.
        // release keeps all those lookups blocked until admission is checked.
        CountDownLatch entered = new CountDownLatch(policy.limits().maxConcurrentChecks());
        CountDownLatch release = new CountDownLatch(1);
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        client.onLookup = () -> awaitLookup(entered, release);
        // CAAPolicy uses fixed production limits; occupy every allowed slot.
        ExecutorService workers = Executors.newFixedThreadPool(policy.limits().maxConcurrentChecks());

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy)) {
            List<Future<CAADecision>> pending = new ArrayList<>();

            for (int i = 0; i < policy.limits().maxConcurrentChecks(); i++) {
                CAARequest workerRequest = request(NAME);
                Future<CAADecision> check = workers.submit(() -> validator.validate(workerRequest));
                pending.add(check);
            }
            // await() confirms the slots are occupied before the extra call;
            // the timeout prevents a broken fixture from hanging the suite.
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            assertEquals(policy.limits().maxConcurrentChecks(), client.queries.size());

            CAARequest certificateRequest = request(NAME);

            CAADecision rejected = validator.validate(certificateRequest);

            assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED, rejected.names().get(0).failure().orElseThrow().reason());
            assertEquals(policy.limits().maxConcurrentChecks(), client.queries.size());
            release.countDown();

            for (Future<CAADecision> check : pending) {
                CAADecision completed = check.get(2, TimeUnit.SECONDS);

                assertEquals(CAADecision.Outcome.ALLOW, completed.outcome());
            }
            client.onLookup = () -> {
                // Subsequent requests no longer wait on the concurrency fixture.
            };
            CAADecision allowed = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
        } finally {
            release.countDown();
            workers.shutdownNow();
        }
    }

    /**
     * Pause a lookup, close the validator twice, then release the DNS grant.
     * The pending validation must return ERROR/CANCELLED and close the client only once.
     */
    @Test
    void shutdownDuringLookupCannotReturnAnAllowDecision() throws Exception {
        // Pause the worker inside DNS so close() happens during validation.
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        client.onLookup = () -> awaitLookup(entered, release);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAARequest certificateRequest = request(NAME);
            Future<CAADecision> pending = executor.submit(() -> validator.validate(certificateRequest));

            assertTrue(entered.await(2, TimeUnit.SECONDS));
            validator.close();
            validator.close();
            release.countDown();
            // Future.get() waits for the worker's decision and surfaces any
            // worker exception on the test thread, with a bounded wait.
            CAADecision result = pending.get(2, TimeUnit.SECONDS);

            assertEquals(CAADecision.Outcome.ERROR, result.outcome());
            assertEquals(DNSLookupException.Reason.CANCELLED, result.names().get(0).failure().orElseThrow().reason());
            assertEquals(1, client.closes.get());
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    /**
     * Build long attacker-controlled parameter tags that stress parser depth.
     * They must deny without stack overflow, while a separate valid grant still allows.
     */
    @Test
    void largeParameterTagsAreRejectedWithoutOverflowAndDoNotOverrideOtherGrants() throws Exception {
        for (int repeats : List.of(5000, 32000)) {
            InMemoryDNSClient client = new InMemoryDNSClient();

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                String value = ISSUER + ";" + "a-".repeat(repeats) + "a=x";
                client.put("www.customer.test", record("www.customer.test", 0, "issue", value));
                CAARequest certificateRequest = request(NAME);

                CAADecision denied = validator.validate(certificateRequest);

                assertEquals(CAADecision.Outcome.DENY, denied.outcome());

                client.put("www.customer.test", record("www.customer.test", 0, "issue", value),
                        record("www.customer.test", 0, "issue", ISSUER));
                CAADecision allowed = validator.validate(certificateRequest);

                assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
            }
        }
    }

    /**
     * Place dns-01 at the beginning of a very long valid method list. Verify
     * allowance, then append malformed suffixes to ensure parsing does not stop early.
     */
    @Test
    void largeMethodListsAreParsedCompletelyWithoutOverflow() throws Exception {
        CAARequest.IssuanceContext context = new CAARequest.IssuanceContext(Optional.empty(), Optional.of("dns-01"));
        CAARequest request = new CAARequest(List.of(NAME), Map.of(NAME, context));

        for (int repeats : List.of(5000, 32000)) {
            InMemoryDNSClient client = new InMemoryDNSClient();

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                String value = ISSUER + ";validationmethods=dns-01," + "x,".repeat(repeats) + "http-01";
                client.put("www.customer.test", record("www.customer.test", 0, "issue", value));

                CAADecision allowed = validator.validate(request);

                assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());

                for (String suffix : List.of(",", ",bad_label", ",bad label")) {
                    client.put("www.customer.test", record("www.customer.test", 0, "issue", value + suffix));

                    CAADecision denied = validator.validate(request);

                    assertEquals(CAADecision.Outcome.DENY, denied.outcome());
                }
            }
        }
    }

    /**
     * Accept permitted spaces/tabs around parameter separators, then reject
     * invalid tags and embedded value spaces. Each case evaluates a real issue value.
     */
    @Test
    void parameterWhitespaceAndSyntaxFollowTheCaaGrammar() throws Exception {
        CAARequest.IssuanceContext context = new CAARequest.IssuanceContext(Optional.empty(), Optional.of("dns-01"));
        CAARequest request = new CAARequest(List.of(NAME), Map.of(NAME, context));
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue",
                    "\t" + ISSUER + " ; \tvalidationmethods\t = \tdns-01\t"));

            CAADecision allowed = validator.validate(request);

            assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());

            for (String parameter : List.of("-key=x", "key-=x", "key name=x", "key\tname=x", "=x", "key=has space")) {
                client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER + ";" + parameter));

                CAADecision denied = validator.validate(request);

                assertEquals(CAADecision.Outcome.DENY, denied.outcome(), parameter);
                assertEquals(CAADecision.Reason.ISSUER_NOT_AUTHORIZED,
                        denied.names().get(0).reason(), parameter);
            }
        }
    }

    /**
     * Secure evidence from an enforcing provider must reach policy evaluation.
     */
    @Test
    void delegatedSecureAnswerCanAuthorizeIssuance() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAADNSClient.CAARecord grant = record("www.customer.test", 0, "issue", ISSUER);
        CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                "fixture", NAME.baseName(), 0, true, CAADNSClient.ValidationStatus.SECURE, Instant.now(), "fixture", Optional.empty());
        CAADNSClient.LookupResult lookup = new CAADNSClient.LookupResult(
                NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                List.of(grant), List.of(), List.of(response), Optional.empty());
        client.answers.put(NAME.baseName(), lookup);
        CAARequest request = request(NAME);

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
        }
    }

    /**
     * AD-clear evidence is accepted under the enforcing-resolver contract.
     * UNCLASSIFIED does not independently prove that the domain is insecure.
     */
    @Test
    void delegatedUnclassifiedAnswerCanAuthorizeIssuance() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAADNSClient.CAARecord grant = record("www.customer.test", 0, "issue", ISSUER);
        CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                "fixture", NAME.baseName(), 0, false, CAADNSClient.ValidationStatus.UNCLASSIFIED, Instant.now(), "fixture", Optional.empty());
        CAADNSClient.LookupResult lookup = new CAADNSClient.LookupResult(
                NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                List.of(grant), List.of(), List.of(response), Optional.empty());
        client.answers.put(NAME.baseName(), lookup);
        CAARequest request = request(NAME);

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(request);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
        }
    }

    /**
     * A well-formed grant for another candidate must not authorize this name.
     * The engine checks the returned lookup identity before trusting its policy.
     */
    @Test
    void mismatchedLookupCandidateCannotAuthorizeIssuance() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            DNSDomainName unrelated = domain("other.customer.test");
            CAADNSClient.CAARecord grant = record("other.customer.test", 0, "issue", ISSUER);
            CAADNSClient.ResponseEvidence response = evidence(unrelated);
            CAADNSClient.LookupResult unrelatedLookup = new CAADNSClient.LookupResult(
                    unrelated, unrelated, CAADNSClient.LookupKind.RRSET,
                    List.of(grant), List.of(), List.of(response), Optional.empty());
            client.answers.put(NAME.baseName(), unrelatedLookup);
            CAARequest certificateRequest = request(NAME);

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            assertEquals(DNSLookupException.Reason.MALFORMED_RESPONSE,
                    decision.names().get(0).failure().orElseThrow().reason());

            assertEquals(List.of("www.customer.test."), client.queries);
        }
    }

    /**
     * NXDOMAIN at the leaf is established absence, so discovery must consult
     * the original parent. The parent's grant can authorize the requested name.
     */
    @Test
    void nxdomainContinuesAtTheOriginalParent() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            DNSDomainName leaf = NAME.baseName();
            client.answers.put(leaf, nxdomain(leaf, leaf, List.of()));
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER));
            CAARequest certificateRequest = request(NAME);

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
            assertEquals(List.of("www.customer.test.", "customer.test."), client.queries);
        }
    }

    /**
     * NXDOMAIN after an alias must not move parent discovery to the target's
     * tree. A denial there makes querying the wrong parent observable.
     */
    @Test
    void aliasNxdomainContinuesAtTheOriginalParent() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            DNSDomainName leaf = NAME.baseName();
            DNSDomainName target = domain("edge.hosting.test");
            CAADNSClient.AliasStep alias = new CAADNSClient.AliasStep(
                    leaf, target, CAADNSClient.AliasKind.CNAME, 60);
            client.answers.put(leaf, nxdomain(leaf, target, List.of(alias)));
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER));
            client.put("hosting.test", record("hosting.test", 0, "issue", ";"));
            CAARequest certificateRequest = request(NAME);

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
            assertEquals(List.of("www.customer.test.", "customer.test."), client.queries);
        }
    }

    /**
     * Let the first name spend the attempt's entire query allowance. The next
     * name must fail before querying; a new validation attempt gets a fresh budget.
     */
    @Test
    void queryAllowanceIsSharedAcrossCertificateNames() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
            client.put("api.customer.test", record("api.customer.test", 0, "issue", ISSUER));
            client.queryReservations = policy().limits().maxQueries();
            CAARequest certificateRequest = request(NAME, name("api.customer.test", false));

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ALLOW, decision.names().get(0).outcome());
            assertEquals(CAADecision.Outcome.ERROR, decision.names().get(1).outcome());
            assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                    decision.names().get(1).failure().orElseThrow().reason());

            assertEquals(List.of("www.customer.test."), client.queries);
            // A separate request must receive a new allowance.
            CAARequest nextRequest = request(NAME);

            CAADecision allowed = validator.validate(nextRequest);

            assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
        }
    }

    /**
     * Repeated DNS failures must not leak admission slots. More attempts than
     * the slot count must all reach DNS, and a subsequent grant must still allow.
     */
    @Test
    void dnsFailureReleasesAdmissionForTheNextAttempt() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.error = true;
            int attempts = policy().limits().maxConcurrentChecks() + 1;

            for (int i = 0; i < attempts; i++) {
                CAARequest certificateRequest = request(NAME);

                CAADecision decision = validator.validate(certificateRequest);

                assertEquals(DNSLookupException.Reason.RCODE_FAILURE,
                        decision.names().get(0).failure().orElseThrow().reason());
            }
            assertEquals(attempts, client.queries.size());

            client.error = false;
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
            CAARequest nextRequest = request(NAME);

            CAADecision allowed = validator.validate(nextRequest);

            assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
        }
    }

    /**
     * Interrupted attempts must release admission too. Clear the interruption
     * between attempts, then prove an ordinary request can still reach DNS.
     */
    @Test
    void cancellationReleasesAdmissionForTheNextAttempt() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            int attempts = policy().limits().maxConcurrentChecks() + 1;

            for (int i = 0; i < attempts; i++) {
                Thread.currentThread().interrupt();

                try {
                    CAARequest certificateRequest = request(NAME);

                    CAADecision decision = validator.validate(certificateRequest);

                    assertEquals(DNSLookupException.Reason.CANCELLED,
                            decision.names().get(0).failure().orElseThrow().reason());

                    assertTrue(Thread.currentThread().isInterrupted());
                } finally {
                    // Do not leave the JUnit thread interrupted for later tests.
                    Thread.interrupted();
                }
            }
            assertTrue(client.queries.isEmpty());

            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
            CAARequest nextRequest = request(NAME);

            CAADecision allowed = validator.validate(nextRequest);

            assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
        }
    }

    /**
     * Signals lookup entry, then waits for the test thread to release the worker.
     * Assertion/interruption failures propagate through the worker's Future.
     */
    private static void awaitLookup(CountDownLatch entered, CountDownLatch release) {
        entered.countDown();

        try {
            assertTrue(release.await(3, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }

    private static CAARequest requestWithContext(String accountUri, String validationMethod) {
        CAARequest.IssuanceContext context = new CAARequest.IssuanceContext(
                Optional.of(URI.create(accountUri)), Optional.of(validationMethod));
        return new CAARequest(List.of(NAME), Map.of(NAME, context));
    }

    private static CAADNSClient.LookupResult nxdomain(DNSDomainName candidate, DNSDomainName target,
            List<CAADNSClient.AliasStep> aliases) {
        CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                "fixture", candidate, 3, false, CAADNSClient.ValidationStatus.UNCLASSIFIED, Instant.now(), "fixture", Optional.empty());
        return new CAADNSClient.LookupResult(candidate, target, CAADNSClient.LookupKind.NXDOMAIN,
                List.of(), aliases, List.of(response), Optional.empty());
    }

    private static CAAPolicy policy() {
        return new CAAPolicy(Set.of(ISSUER));
    }

    private static CAARequest request(CAARequest.CertificateName... names) {
        return new CAARequest(List.of(names), Map.of());
    }

    private static DNSDomainName domain(String text) {
        return new DNSDomainName(text + ".");
    }

    private static CAARequest.CertificateName name(String text, boolean wildcard) {
        return new CAARequest.CertificateName(domain(text), wildcard);
    }

    private static CAADNSClient.CAARecord record(String owner, int flags, String tag, String value) {
        return new CAADNSClient.CAARecord(domain(owner), 60, flags, tag, value.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Diagnostic evidence deliberately lacking trust for rejection tests.
     */
    private static CAADNSClient.ResponseEvidence untrustedEvidence(DNSDomainName candidate) {
        return new CAADNSClient.ResponseEvidence("fixture", candidate, 0, false,
                CAADNSClient.ValidationStatus.UNTRUSTED,
                Instant.now(), "fixture", Optional.empty());
    }

    private static CAADNSClient.ResponseEvidence evidence(DNSDomainName candidate) {
        return new CAADNSClient.ResponseEvidence("fixture", candidate, 0, false, CAADNSClient.ValidationStatus.UNCLASSIFIED, Instant.now(), "fixture", Optional.empty());
    }

    /**
     * Returns configured lookups, or NODATA for unconfigured candidates.
     * Records query order; the callback lets concurrency tests pause a lookup.
     * queryReservations models follow-up queries charged to the same budget.
     */
    private static final class InMemoryDNSClient implements CAADNSClient {
        final List<String> queries = new CopyOnWriteArrayList<>();
        final Map<DNSDomainName, LookupResult> answers = new HashMap<>();
        boolean error;
        int queryReservations = 1;
        Runnable onLookup = () -> {
            // Most tests resolve immediately; concurrency tests install a wait.
        };
        final AtomicInteger closes = new AtomicInteger();
        @Override
        public LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget) throws DNSLookupException {
            // Extra reservations model follow-up queries within one lookup.
            for (int i = 0; i < queryReservations; i++) {
                budget.reserveQuery();
            }
            queries.add(candidate.asciiAbsoluteName());
            onLookup.run();
            if (error) {
                throw DefaultCAAValidator.failure(DNSLookupException.Reason.RCODE_FAILURE, "fixture failure");
            }
            LookupResult configured = answers.get(candidate);
            if (configured != null) {
                return configured;
            }

            // Unconfigured names establish absence so real parent discovery runs.
            return new LookupResult(candidate, candidate, LookupKind.NODATA,
                    List.of(), List.of(), List.of(evidence(candidate)), Optional.empty());
        }

        void put(String name, CAARecord... records) {
            DNSDomainName owner = domain(name);
            answers.put(owner, new LookupResult(owner, owner, LookupKind.RRSET, List.of(records), List.of(),
                    List.of(evidence(owner)), Optional.empty()));
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }
    }
}

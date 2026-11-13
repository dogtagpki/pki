// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

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
     * Both NODATA and NXDOMAIN after an alias continue at the original parent.
     * A restrictive target parent exposes accidental traversal of the wrong tree.
     */
    @Test
    void aliasAbsenceClimbsOriginalParentRatherThanAliasParent() throws Exception {
        for (CAADNSClient.LookupKind kind : List.of(CAADNSClient.LookupKind.NODATA, CAADNSClient.LookupKind.NXDOMAIN)) {
            InMemoryDNSClient client = new InMemoryDNSClient();
            DNSDomainName leaf = NAME.baseName();
            DNSDomainName target = domain("edge.hosting.test");
            CAADNSClient.AliasStep alias = new CAADNSClient.AliasStep(leaf, target, CAADNSClient.AliasKind.CNAME, 60);
            int rcode = kind == CAADNSClient.LookupKind.NXDOMAIN ? 3 : 0;
            CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                    "fixture", leaf, rcode, false, CAADNSClient.ValidationStatus.UNCLASSIFIED,
                    "fixture", Optional.empty());
            client.answers.put(leaf, new CAADNSClient.LookupResult(
                    leaf, target, kind, List.of(), List.of(alias), List.of(response), Optional.empty()));
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER));
            client.put("hosting.test", record("hosting.test", 0, "issue", ";"));

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                CAADecision decision = validator.validate(request(NAME));

                assertEquals(CAADecision.Outcome.ALLOW, decision.outcome(), kind.toString());
                assertEquals(domain("customer.test"), decision.names().get(0).relevantOwner().orElseThrow());
                assertEquals(List.of("www.customer.test.", "customer.test."), client.queries, kind.toString());
            }
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
     * Each malformed value fails as a sole grant, but cannot cancel an
     * independent valid grant. Preserve the syntax-specific denial reason.
     */
    @Test
    void malformedGrantsDoNotAuthorizeOrOverrideIndependentGrants() throws Exception {
        for (String value : List.of(";", "", "%%%%%", ISSUER + "; malformed", ISSUER + ";x=a b")) {
            InMemoryDNSClient client = new InMemoryDNSClient();
            CAADNSClient.CAARecord malformed = record("www.customer.test", 0, "issue", value);
            client.put("www.customer.test", malformed);
            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                CAADecision denied = validator.validate(request(NAME));

                assertEquals(CAADecision.Outcome.DENY, denied.outcome(), value);
                assertEquals(CAADecision.Reason.ISSUER_NOT_AUTHORIZED,
                        denied.names().get(0).reason(), value);

                // Keep the malformed record while adding a case-insensitive grant.
                client.put("www.customer.test", malformed,
                        record("www.customer.test", 0, "issue", ISSUER.toUpperCase()));
                CAADecision allowed = validator.validate(request(NAME));

                assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome(), value);
                assertEquals(CAADecision.Reason.ISSUER_AUTHORIZED, allowed.names().get(0).reason(), value);
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
     * Reserved bits do not impose restrictions. Critical bits reject an unknown
     * property both alone and alongside an otherwise valid issuer grant.
     */
    @Test
    void unknownPropertyFlagsControlWhetherTheRrsetIsDenied() throws Exception {
        record FlagCase(String scenario, int flags, boolean includeGrant,
                CAADecision.Outcome expectedOutcome, CAADecision.Reason expectedReason) {
        }
        List<FlagCase> cases = List.of(
                new FlagCase("reserved bit alone leaves issuance unrestricted", 1, false,
                        CAADecision.Outcome.ALLOW, CAADecision.Reason.NO_RESTRICTION),
                new FlagCase("critical property alone denies issuance", 128, false,
                        CAADecision.Outcome.DENY, CAADecision.Reason.UNKNOWN_CRITICAL_PROPERTY),
                new FlagCase("critical plus reserved bit overrides a valid grant", 129, true,
                        CAADecision.Outcome.DENY, CAADecision.Reason.UNKNOWN_CRITICAL_PROPERTY),
                new FlagCase("noncritical property permits the independent grant", 0, true,
                        CAADecision.Outcome.ALLOW, CAADecision.Reason.ISSUER_AUTHORIZED));

        for (FlagCase test : cases) {
            InMemoryDNSClient client = new InMemoryDNSClient();
            CAADNSClient.CAARecord unknown = record("www.customer.test", test.flags(), "future", "opaque");
            if (test.includeGrant()) {
                // Put the grant first to catch an unsafe early return before the critical property.
                client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER), unknown);
            } else {
                client.put("www.customer.test", unknown);
            }
            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                CAADecision decision = validator.validate(request(NAME));

                assertEquals(test.expectedOutcome(), decision.outcome(), test.scenario());
                assertEquals(test.expectedReason(), decision.names().get(0).reason(), test.scenario());
            }
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
     * Matching an account in one record and a method in another cannot form a
     * grant. Reverse wire order too, then prove a wholly matching record allows.
     */
    @Test
    void accountAndMethodRestrictionsCannotMergeAcrossGrants() throws Exception {
        CAADNSClient.CAARecord accountA = record("www.customer.test", 0, "issue",
                ISSUER + ";accounturi=https://acme.example/acct/A;validationmethods=dns-01");
        CAADNSClient.CAARecord accountB = record("www.customer.test", 0, "issue",
                ISSUER + ";accounturi=https://acme.example/acct/B;validationmethods=http-01");
        for (List<CAADNSClient.CAARecord> records : List.of(List.of(accountA, accountB), List.of(accountB, accountA))) {
            InMemoryDNSClient client = new InMemoryDNSClient();
            client.put("www.customer.test", records.toArray(CAADNSClient.CAARecord[]::new));
            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                CAADecision denied = validator.validate(requestWithContext("https://acme.example/acct/A", "http-01"));
                assertEquals(CAADecision.Outcome.DENY, denied.outcome());

                CAADecision allowed = validator.validate(requestWithContext("https://acme.example/acct/A", "dns-01"));
                assertEquals(CAADecision.Outcome.ALLOW, allowed.outcome());
                assertEquals(CAADecision.Reason.ISSUER_AUTHORIZED, allowed.names().get(0).reason());
            }
        }
    }

    /**
     * A present context can still lack the particular fact a grant requires.
     * The other matching fact cannot substitute for the absent one.
     */
    @Test
    void partialContextCannotSatisfyRequiredBindings() throws Exception {
        List<CAARequest.IssuanceContext> contexts = List.of(
                new CAARequest.IssuanceContext(Optional.empty(), Optional.of("dns-01")),
                new CAARequest.IssuanceContext(Optional.of(URI.create("https://acme.example/acct/A")), Optional.empty()));
        for (CAARequest.IssuanceContext context : contexts) {
            InMemoryDNSClient client = new InMemoryDNSClient();
            client.put("www.customer.test", record("www.customer.test", 0, "issue",
                    ISSUER + ";accounturi=https://acme.example/acct/A;validationmethods=dns-01"));
            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                CAADecision decision = validator.validate(new CAARequest(List.of(NAME), Map.of(NAME, context)));

                assertEquals(CAADecision.Outcome.DENY, decision.outcome());
                assertEquals(CAADecision.Reason.MISSING_BINDING_CONTEXT, decision.names().get(0).reason());
            }
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
     * Both accepted statuses can authorize under the enforcing-resolver contract.
     * AD-clear UNCLASSIFIED does not independently prove that a zone is unsigned.
     */
    @Test
    void trustedGrantAssuranceAllowsPolicyEvaluation() throws Exception {
        record AssuranceCase(String scenario, CAADNSClient.ValidationStatus status, boolean ad) {
        }
        List<AssuranceCase> cases = List.of(
                new AssuranceCase("secure response with AD", CAADNSClient.ValidationStatus.SECURE, true),
                new AssuranceCase("accepted response without AD", CAADNSClient.ValidationStatus.UNCLASSIFIED, false));

        for (AssuranceCase test : cases) {
            InMemoryDNSClient client = clientWithGrantEvidence(test.status(), test.ad());

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                CAADecision decision = validator.validate(request(NAME));

                assertEquals(CAADecision.Outcome.ALLOW, decision.outcome(), test.scenario());
                assertEquals(CAADecision.Reason.ISSUER_AUTHORIZED,
                        decision.names().get(0).reason(), test.scenario());
                assertEquals(List.of("www.customer.test."), client.queries, test.scenario());
            }
        }
    }

    /**
     * Untrusted DNS cannot authorize even when AD is set. Use an unrestricted
     * grant and account context to model an answer with stripped binding parameters.
     */
    @Test
    void untrustedGrantIsRejectedRegardlessOfTheAdFlag() throws Exception {
        for (boolean ad : List.of(false, true)) {
            String scenario = ad ? "untrusted response with forged AD" : "untrusted response without AD";
            InMemoryDNSClient client = clientWithGrantEvidence(CAADNSClient.ValidationStatus.UNTRUSTED, ad);

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                CAARequest request = requestWithContext("https://acme.example/acct/B", "dns-01");
                CAADecision decision = validator.validate(request);

                assertEquals(CAADecision.Outcome.ERROR, decision.outcome(), scenario);
                assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                        decision.names().get(0).failure().orElseThrow().reason(), scenario);
                assertEquals(List.of("www.customer.test."), client.queries, scenario);
            }
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
                    "fixture", NAME.baseName(), rcode, false, CAADNSClient.ValidationStatus.UNTRUSTED, "fixture", Optional.empty());
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
     * Exercise issue fallback and issuewild applicability with independent
     * requests. The separate shared-lookup test covers mixed wildcard identities.
     */
    @Test
    void wildcardStatusSelectsTheApplicableProperty() throws Exception {
        record WildcardCase(String scenario, String tag, String value, boolean wildcard,
                CAADecision.Outcome expectedOutcome, CAADecision.Reason expectedReason) {
        }
        List<WildcardCase> cases = List.of(
                new WildcardCase("wildcard falls back to issue", "issue", ISSUER, true,
                        CAADecision.Outcome.ALLOW, CAADecision.Reason.ISSUER_AUTHORIZED),
                new WildcardCase("issuewild does not restrict an ordinary name", "issuewild", ";", false,
                        CAADecision.Outcome.ALLOW, CAADecision.Reason.NO_RESTRICTION),
                new WildcardCase("issuewild denies a wildcard name", "issuewild", ";", true,
                        CAADecision.Outcome.DENY, CAADecision.Reason.ISSUER_NOT_AUTHORIZED));

        for (WildcardCase test : cases) {
            InMemoryDNSClient client = new InMemoryDNSClient();
            client.put("www.customer.test", record("www.customer.test", 0, test.tag(), test.value()));
            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
                CAADecision decision = validator.validate(request(name("www.customer.test", test.wildcard())));

                assertEquals(test.expectedOutcome(), decision.outcome(), test.scenario());
                assertEquals(test.expectedReason(), decision.names().get(0).reason(), test.scenario());
            }
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
     * Return an authorized RRset with both untrusted and secure observations
     * from a delegated provider. A secure final observation cannot repair earlier gaps.
     */
    @Test
    void secureFinalAnswerCannotCoverAnUnvalidatedEarlierObservation() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADNSClient.ResponseEvidence secure = new CAADNSClient.ResponseEvidence("fixture", NAME.baseName(), 0, true,
                    CAADNSClient.ValidationStatus.SECURE,
                    "fixture", Optional.empty());
            CAADNSClient.CAARecord grant = record("www.customer.test", 0, "issue", ISSUER);
            CAADNSClient.ResponseEvidence untrusted = untrustedEvidence(NAME.baseName());
            CAADNSClient.LookupResult lookup = new CAADNSClient.LookupResult(
                    NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                    List.of(grant), List.of(), List.of(untrusted, secure), Optional.empty());
            client.answers.put(NAME.baseName(), lookup);
            CAARequest certificateRequest = request(NAME);

            CAADecision decision = validator.validate(certificateRequest);

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            // Keep the failed observation for diagnostics without accepting
            // the lookup into successful discovery.
            assertEquals(List.of(untrusted), decision.names().get(0).failure().orElseThrow().partialResponses());
            assertTrue(decision.names().get(0).discovery().isEmpty());
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
     * After a completion timeout, occupy every validator slot with concurrent lookups. An extra
     * attempt must fail without DNS; after releasing the blocked calls, admission recovers.
     */
    @Test
    void completionTimeoutRestoresFullCapacityAndSaturationRejectsWithoutDns() throws Exception {
        CAAPolicy policy = policy();
        // Each worker decrements entered after reaching the DNS fixture.
        // release keeps all those lookups blocked until admission is checked.
        CountDownLatch entered = new CountDownLatch(policy.limits().maxConcurrentChecks());
        CountDownLatch release = new CountDownLatch(1);
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        AtomicLong nanos = new AtomicLong(System.nanoTime());
        Clock clock = new CompletionClock(() -> nanos.addAndGet(policy.limits().totalTimeout().toNanos()));
        // CAAPolicy uses fixed production limits; occupy every allowed slot.
        ExecutorService workers = Executors.newFixedThreadPool(policy.limits().maxConcurrentChecks());

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy, clock, nanos::get)) {
            // A timeout after DNS must return its slot before the workers start.
            CAADecision timedOut = validator.validate(request(NAME));
            assertEquals(DNSLookupException.Reason.TIMEOUT, timedOut.names().get(0).failure().orElseThrow().reason());
            assertEquals(List.of(NAME.baseName().asciiAbsoluteName()), client.queries);

            client.queries.clear();
            client.onLookup = () -> awaitLookup(entered, release);
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
     * Pause every admitted worker after DNS completes but before decision
     * construction. The next caller must still encounter the concurrency limit.
     */
    @Test
    void admissionIsHeldUntilDecisionConstructionCompletes() throws Exception {
        int capacity = policy().limits().maxConcurrentChecks();
        CountDownLatch lookupsEntered = new CountDownLatch(capacity);
        CountDownLatch releaseLookups = new CountDownLatch(1);
        CountDownLatch completionsEntered = new CountDownLatch(capacity);
        CountDownLatch releaseCompletions = new CountDownLatch(1);
        AtomicBoolean pauseCompletion = new AtomicBoolean();
        Thread caller = Thread.currentThread();
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        client.onLookup = () -> awaitLookup(lookupsEntered, releaseLookups);
        Clock completionClock = new Clock() {
            @Override
            public ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(ZoneId zone) {
                return Clock.fixed(instant(), zone);
            }

            @Override
            public Instant instant() {
                if (pauseCompletion.get() && Thread.currentThread() != caller) {
                    awaitLookup(completionsEntered, releaseCompletions);
                }
                return Instant.now();
            }
        };
        ExecutorService workers = Executors.newFixedThreadPool(capacity);

        // Only admission is under test. Scheduler delays at either latch must
        // not consume the validator's five-second DNS deadline.
        long fixedNanos = System.nanoTime();
        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy(), completionClock, () -> fixedNanos)) {
            List<Future<CAADecision>> attempts = new ArrayList<>();
            for (int i = 0; i < capacity; i++) {
                attempts.add(workers.submit(() -> validator.validate(request(NAME))));
            }
            assertTrue(lookupsEntered.await(2, TimeUnit.SECONDS));

            // Move all workers into the completion phase, keeping them inside
            // validate() while the main thread attempts one additional check.
            pauseCompletion.set(true);
            releaseLookups.countDown();
            assertTrue(completionsEntered.await(2, TimeUnit.SECONDS));

            CAADecision rejected = validator.validate(request(NAME));

            assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                    rejected.names().get(0).failure().orElseThrow().reason());
            assertEquals(capacity, client.queries.size());
            releaseCompletions.countDown();
            for (Future<CAADecision> attempt : attempts) {
                assertEquals(CAADecision.Outcome.ALLOW, attempt.get(2, TimeUnit.SECONDS).outcome());
            }

            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(NAME)).outcome());
        } finally {
            releaseLookups.countDown();
            releaseCompletions.countDown();
            workers.shutdownNow();
        }
    }

    /**
     * Close on the final lookup after earlier names allowed and denied. Its
     * own DNS failure and the earlier denial must survive cancellation of the
     * pending approval, together with their original discovery evidence.
     */
    @Test
    void shutdownPreservesExistingDenialsAndDnsFailures() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAARequest.CertificateName deniedName = name("denied.customer.test", false);
        CAARequest.CertificateName failedName = name("failed.customer.test", false);
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        client.put("denied.customer.test", record("denied.customer.test", 0, "issue", ";"));
        CAADNSClient.LookupResult grant = client.answers.get(NAME.baseName());
        CAADNSClient.LookupResult denial = client.answers.get(deniedName.baseName());

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            client.onLookup = () -> {
                String candidate = client.queries.get(client.queries.size() - 1);
                if (candidate.equals(failedName.baseName().asciiAbsoluteName())) {
                    client.error = true;
                    validator.close();
                }
            };

            CAADecision decision = validator.validate(request(NAME, deniedName, failedName));

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            CAADecision.NameDecision cancelled = decision.names().get(0);
            assertEquals(CAADecision.Outcome.ERROR, cancelled.outcome());
            assertEquals(DNSLookupException.Reason.CANCELLED, cancelled.failure().orElseThrow().reason());
            assertEquals(Optional.of(NAME.baseName()), cancelled.relevantOwner());
            assertEquals(List.of(grant), cancelled.discovery());

            assertPreservedDenialAndDnsFailure(decision, deniedName, denial);
            assertEquals(1, client.closes.get());
        }
    }

    /**
     * Shutdown can occur while the completed decision is being built
     * or at the last budget check. Shutdown retains CANCELLED precedence for
     * pending approvals, along with their owner and discovery evidence.
     */
    @Test
    void shutdownDuringCompletionPreservesCancellation() throws Exception {
        for (String phase : List.of("completion wall read", "final budget check", "final budget timeout")) {
            long tick = System.nanoTime();
            InMemoryDNSClient client = new InMemoryDNSClient();
            client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
            var lookup = client.answers.get(NAME.baseName());
            AtomicReference<DefaultCAAValidator> active = new AtomicReference<>();
            AtomicBoolean finalCheck = new AtomicBoolean();
            Clock clock = new CompletionClock(() -> {
                if (!phase.equals("completion wall read")) {
                    finalCheck.set(true);
                } else {
                    active.get().close();
                }
            });

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy(), clock, () -> {
                // Close at the final budget read, optionally coinciding with timeout.
                if (finalCheck.get()) {
                    active.get().close();
                    if (phase.equals("final budget timeout")) {
                        return tick + policy().limits().totalTimeout().toNanos();
                    }
                }
                return tick;
            })) {
                active.set(validator);
                CAADecision decision = validator.validate(request(NAME));
                CAADecision.NameDecision cancelled = decision.names().get(0);

                assertEquals(CAADecision.Outcome.ERROR, decision.outcome(), phase);
                assertEquals(CAADecision.Reason.DNS_FAILURE, cancelled.reason(), phase);
                assertEquals(DNSLookupException.Reason.CANCELLED,
                        cancelled.failure().orElseThrow().reason(), phase);
                assertEquals(Optional.of(NAME.baseName()), cancelled.relevantOwner(), phase);
                assertEquals(List.of(lookup), cancelled.discovery(), phase);
                assertEquals(1, client.closes.get(), phase);
            }
        }
    }

    /**
     * Time spent sampling the initial wall clock consumes the same attempt
     * budget. Expiry there must prevent even the first DNS lookup.
     */
    @Test
    void initialWallClockReadConsumesTheAttemptBudget() throws Exception {
        AtomicLong nanos = new AtomicLong();
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        Clock clock = new CompletionClock(1, () -> nanos.set(policy().limits().totalTimeout().toNanos()));

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy(), clock, nanos::get)) {
            CAADecision decision = validator.validate(request(NAME));

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            assertEquals(DNSLookupException.Reason.TIMEOUT, decision.names().get(0).failure().orElseThrow().reason());
            assertTrue(client.queries.isEmpty());
        }
    }

    /**
     * Exhaust the budget after a child absence or a selected parent RRset.
     * Preserve the selected owner only when discovery actually reached it.
     */
    @Test
    void perNameTimeoutRetainsTheSelectedParentOwner() throws Exception {
        for (boolean selectParent : List.of(false, true)) {
            InMemoryDNSClient client = new InMemoryDNSClient();
            DNSDomainName parent = domain("customer.test");
            client.put("customer.test", record("customer.test", 0, "issue", ISSUER));
            AtomicLong nanos = new AtomicLong(System.nanoTime());
            String timeoutAt = selectParent ? parent.asciiAbsoluteName() : NAME.baseName().asciiAbsoluteName();
            client.onLookup = () -> {
                String question = client.queries.get(client.queries.size() - 1);
                if (question.equals(timeoutAt)) {
                    nanos.addAndGet(policy().limits().totalTimeout().toNanos());
                }
            };

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy(), Clock.systemUTC(), nanos::get)) {
                CAADecision decision = validator.validate(request(NAME));
                CAADecision.NameDecision failed = decision.names().get(0);

                assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
                assertEquals(DNSLookupException.Reason.TIMEOUT, failed.failure().orElseThrow().reason());
                assertEquals(selectParent ? Optional.of(parent) : Optional.empty(), failed.relevantOwner());
                assertEquals(selectParent ? 2 : 1, failed.discovery().size());
                if (selectParent) {
                    assertEquals(client.answers.get(parent), failed.discovery().get(1));
                }
            }
        }
    }

    /**
     * Expire the attempt during completion, after all per-name checks passed.
     * Only the approval becomes TIMEOUT; prior policy and DNS failures survive.
     */
    @Test
    void completionDeadlinePreservesDenialsDnsFailuresAndDiscovery() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAARequest.CertificateName deniedName = name("denied.customer.test", false);
        CAARequest.CertificateName failedName = name("failed.customer.test", false);
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        client.put("denied.customer.test", record("denied.customer.test", 0, "issue", ";"));
        CAADNSClient.LookupResult grant = client.answers.get(NAME.baseName());
        CAADNSClient.LookupResult denial = client.answers.get(deniedName.baseName());
        client.onLookup = () -> client.error = client.queries.get(client.queries.size() - 1)
                .equals(failedName.baseName().asciiAbsoluteName());

        // The second wall-clock read starts completion. Advance only monotonic
        // time to the exact deadline, with no sleep or host-clock changes.
        AtomicLong nanos = new AtomicLong(System.nanoTime());
        Clock clock = new CompletionClock(() -> nanos.addAndGet(policy().limits().totalTimeout().toNanos()));
        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy(), clock, nanos::get)) {
            CAADecision decision = validator.validate(request(NAME, deniedName, failedName));

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            CAADecision.NameDecision timedOut = decision.names().get(0);
            assertEquals(CAADecision.Reason.DNS_FAILURE, timedOut.reason());
            assertEquals(DNSLookupException.Reason.TIMEOUT, timedOut.failure().orElseThrow().reason());
            assertEquals(Optional.of(NAME.baseName()), timedOut.relevantOwner());
            assertEquals(List.of(grant), timedOut.discovery());

            assertPreservedDenialAndDnsFailure(decision, deniedName, denial);

            // A follow-up request can be admitted with a fresh deadline.
            // One success does not establish that every permit was released.
            client.error = false;
            client.onLookup = () -> {};
            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(NAME)).outcome());
        }
    }

    /**
     * Interrupt during completion after the last per-name cancellation check.
     * Return CANCELLED with evidence intact and preserve the caller's flag.
     */
    @Test
    void completionInterruptionInvalidatesApprovalAndPreservesTheFlag() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        client.put("www.customer.test", record("www.customer.test", 0, "issue", ISSUER));
        CAADNSClient.LookupResult grant = client.answers.get(NAME.baseName());
        Clock clock = new CompletionClock(() -> Thread.currentThread().interrupt());

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy(), clock)) {
            try {
                CAADecision decision = validator.validate(request(NAME));

                assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
                CAADecision.NameDecision cancelled = decision.names().get(0);
                assertEquals(DNSLookupException.Reason.CANCELLED, cancelled.failure().orElseThrow().reason());
                assertEquals(Optional.of(NAME.baseName()), cancelled.relevantOwner());
                assertEquals(List.of(grant), cancelled.discovery());
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                // Clear only the test's interruption before reusing the JUnit worker.
                Thread.interrupted();
            }

            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(NAME)).outcome());
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
     * Two names consume the complete alias allowance through separate chains.
     * A third name must fail on its first alias, while a new attempt can use it.
     */
    @Test
    void aliasAllowanceIsSharedAcrossCertificateNames() throws Exception {
        InMemoryDNSClient client = new InMemoryDNSClient();
        List<CAARequest.CertificateName> names = List.of(
                NAME, name("api.customer.test", false), name("mail.customer.test", false));
        int halfAllowance = policy().limits().maxAliases() / 2;
        for (int i = 0; i < names.size(); i++) {
            DNSDomainName candidate = names.get(i).baseName();
            DNSDomainName current = candidate;
            List<CAADNSClient.AliasStep> aliases = new ArrayList<>();
            int count = i < 2 ? halfAllowance : 1;
            for (int hop = 0; hop < count; hop++) {
                DNSDomainName target = domain("alias-" + i + "-" + hop + ".hosting.test");
                aliases.add(new CAADNSClient.AliasStep(current, target, CAADNSClient.AliasKind.CNAME, 60));
                current = target;
            }
            CAADNSClient.CAARecord grant = new CAADNSClient.CAARecord(
                    current, 60, 0, "issue", ISSUER.getBytes(StandardCharsets.US_ASCII));
            client.answers.put(candidate, new CAADNSClient.LookupResult(
                    candidate, current, CAADNSClient.LookupKind.RRSET,
                    List.of(grant), aliases, List.of(evidence(candidate)), Optional.empty()));
        }

        try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy())) {
            CAADecision decision = validator.validate(new CAARequest(names, Map.of()));

            assertEquals(CAADecision.Outcome.ERROR, decision.outcome());
            assertEquals(CAADecision.Outcome.ALLOW, decision.names().get(0).outcome());
            assertEquals(CAADecision.Outcome.ALLOW, decision.names().get(1).outcome());
            assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                    decision.names().get(2).failure().orElseThrow().reason());

            // Admission and alias allowances both recover for another attempt.
            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(request(names.get(2))).outcome());
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

    /**
     * Completion failures must preserve the names that already blocked issuance.
     * This assertion is shared; each test keeps its own failure trigger visible.
     */
    private static void assertPreservedDenialAndDnsFailure(CAADecision decision,
            CAARequest.CertificateName deniedName, CAADNSClient.LookupResult denial) {
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

    /**
     * Supplies one unrestricted grant with the explicitly selected trust status
     * and AD observation. Assurance tests keep their expected results separate.
     */
    private static InMemoryDNSClient clientWithGrantEvidence(CAADNSClient.ValidationStatus status, boolean ad) {
        InMemoryDNSClient client = new InMemoryDNSClient();
        CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                "fixture", NAME.baseName(), 0, ad, status, "fixture", Optional.empty());
        CAADNSClient.CAARecord grant = record("www.customer.test", 0, "issue", ISSUER);
        CAADNSClient.LookupResult lookup = new CAADNSClient.LookupResult(
                NAME.baseName(), NAME.baseName(), CAADNSClient.LookupKind.RRSET,
                List.of(grant), List.of(), List.of(response), Optional.empty());
        client.answers.put(NAME.baseName(), lookup);
        return client;
    }

    private static CAARequest requestWithContext(String accountUri, String validationMethod) {
        CAARequest.IssuanceContext context = new CAARequest.IssuanceContext(
                Optional.of(URI.create(accountUri)), Optional.of(validationMethod));
        return new CAARequest(List.of(NAME), Map.of(NAME, context));
    }

    private static CAADNSClient.LookupResult nxdomain(DNSDomainName candidate, DNSDomainName target,
            List<CAADNSClient.AliasStep> aliases) {
        CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                "fixture", candidate, 3, false, CAADNSClient.ValidationStatus.UNCLASSIFIED, "fixture", Optional.empty());
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
                "fixture", Optional.empty());
    }

    private static CAADNSClient.ResponseEvidence evidence(DNSDomainName candidate) {
        return new CAADNSClient.ResponseEvidence("fixture", candidate, 0, false, CAADNSClient.ValidationStatus.UNCLASSIFIED, "fixture", Optional.empty());
    }

    /**
     * Runs one callback at a chosen wall-clock read, defaulting to completion.
     * DNS evidence still uses ordinary timestamps; tests separately control
     * the attempt's elapsed clock or interruption flag at this boundary.
     */
    private static final class CompletionClock extends Clock {
        private final Runnable onCompletion;
        private final int triggerRead;
        private final AtomicInteger reads = new AtomicInteger();

        CompletionClock(Runnable onCompletion) {
            this(2, onCompletion);
        }

        CompletionClock(int triggerRead, Runnable onCompletion) {
            this.triggerRead = triggerRead;
            this.onCompletion = onCompletion;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return Clock.fixed(instant(), zone);
        }

        @Override
        public Instant instant() {
            if (reads.incrementAndGet() == triggerRead) {
                onCompletion.run();
            }
            return Instant.now();
        }
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
                // Model the adapter contract even when the entire alias chain
                // arrives in one response. Every transition consumes allowance.
                for (int i = 0; i < configured.aliases().size(); i++) {
                    budget.reserveAlias();
                }
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

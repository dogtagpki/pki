// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Exercises optional class loading and client ownership, not CAA authorization. */
public class CAADNSClientLoaderTest {

    private static final ClassLoader LOADER = CAADNSClientLoaderTest.class.getClassLoader();
    private static final DNSDomainName NAME = new DNSDomainName("www.example.test.");
    private static TrackingClient lastClient;
    private static final AtomicInteger wrongTypeInitializations = new AtomicInteger();

    @BeforeEach
    void reset() {
        lastClient = null;
    }

    static CAADNSClientProvider.Config config() {
        return new CAADNSClientProvider.Config(Map.of());
    }

    static CAADNSClient open(Class<?> type) throws DNSLookupException {
        return CAADNSClientLoader.open(type.getName(), LOADER, config());
    }

    @Test
    void substitutesProviderClassesWithoutChangingTheEngine() throws Exception {
        for (Class<?> type : List.of(FixtureProvider.class, AlternativeProvider.class)) {
            try (var validator = new DefaultCAAValidator(open(type), new CAAPolicy(Set.of("issuer.test")))) {
                var request = new CAARequest(List.of(new CAARequest.CertificateName(NAME, false)), Map.of());
                assertEquals(CAADecision.Outcome.DENY, validator.validate(request).outcome());
                assertEquals(1, lastClient.lookups.get());
            }
            assertEquals(1, lastClient.closes.get());
        }
    }

    @Test
    void acmeRunsWithoutOptionalAdapterOrDnsjavaInstalled() {
        assertThrows(ClassNotFoundException.class, () -> Class.forName("org.xbill.DNS.Message", false, LOADER));
        assertConfigurationFailure(() -> CAADNSClientLoader.open(
                "org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider", LOADER, config()));
        assertEquals(null, lastClient);
    }

    @Test
    void rejectsBlankMissingAndWrongTypeClasses() {
        for (String name : new String[] { null, "", " ", "not.installed.Provider", String.class.getName() }) {
            assertConfigurationFailure(() -> CAADNSClientLoader.open(name, LOADER, config()));
        }
        assertEquals(null, lastClient);
    }

    @Test
    void requiresPublicNoArgumentConstruction() {
        assertConfigurationFailure(() -> open(PrivateConstructorProvider.class));
        assertEquals(null, lastClient);
    }

    @Test
    void closesClientIfItContradictsItsProvidersFixedBehavior() {
        assertConfigurationFailure(() -> open(WrongModeProvider.class));
        assertEquals(1, lastClient.closes.get());
    }

    @Test
    void rejectsProviderWithoutDeclaredBehaviorBeforeOpeningClient() {
        assertConfigurationFailure(() -> open(MissingBehaviorProvider.class));
        assertEquals(null, lastClient);
    }

    @Test
    void rejectsNullClient() {
        assertConfigurationFailure(() -> open(NullClientProvider.class));
    }

    @Test
    void missingLibraryIsAConfigurationFailureWithNoFallback() {
        assertConfigurationFailure(() -> open(MissingLibraryProvider.class));
        assertEquals(null, lastClient);
    }

    @Test
    void propagatesProviderFailureWithoutTryingAnAlternative() {
        DNSLookupException expected = new DNSLookupException(new DNSLookupException.Failure(
                DNSLookupException.Reason.UNREACHABLE, "Fixture unavailable", List.of()));
        FailingProvider.failure = expected;
        assertSame(expected, assertThrows(DNSLookupException.class, () -> open(FailingProvider.class)));
        assertEquals(null, lastClient);
    }

    @Test
    void cleanupFailureDoesNotMaskConfigurationFailure() {
        DNSLookupException failure = assertConfigurationFailure(() -> open(BrokenCleanupProvider.class));
        assertEquals(1, failure.getSuppressed().length);
        assertEquals(1, lastClient.closes.get());
    }

    @Test
    void rejectingTheWrongSpiTypeDoesNotRunItsStaticInitializer() {
        assertEquals(0, wrongTypeInitializations.get());
        assertConfigurationFailure(() -> open(WrongSpiType.class));
        assertEquals(0, wrongTypeInitializations.get());
    }

    @Test
    void constructorFailureIsConfigurationFailureAndDoesNotOpenAClient() {
        assertConfigurationFailure(() -> open(BrokenConstructorProvider.class));
        assertEquals(null, lastClient);
    }

    @Test
    void aClientWithoutDeclaredBehaviorIsClosed() {
        assertConfigurationFailure(() -> open(NullClientBehaviorProvider.class));
        assertEquals(1, lastClient.closes.get());
    }

    @Test
    void linkageFailureDuringCleanupDoesNotMaskTheOriginalFailure() {
        var error = assertConfigurationFailure(() -> open(LinkageCleanupProvider.class));
        assertEquals(1, error.getSuppressed().length);
        assertEquals(NoClassDefFoundError.class, error.getSuppressed()[0].getClass());
        assertEquals(1, lastClient.closes.get());
    }

    private static DNSLookupException assertConfigurationFailure(CheckedAction action) {
        DNSLookupException e = assertThrows(DNSLookupException.class, action::run);
        assertEquals(DNSLookupException.Reason.CONFIGURATION, e.failure().reason());
        assertFalse(e.getMessage().contains("private resolver configuration"));
        return e;
    }

    private interface CheckedAction {
        void run() throws Exception;
    }

    /** Public no-argument construction follows the configured-component style. */
    public static class FixtureProvider implements CAADNSClientProvider {
        @Override
        public CAADNSClient.ValidationMode validationMode() {
            return CAADNSClient.ValidationMode.UNCHECKED;
        }

        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) throws DNSLookupException {
            if (!config.settings().isEmpty()) {
                throw new DNSLookupException(new DNSLookupException.Failure(DNSLookupException.Reason.CONFIGURATION,
                        "Fixture supports only empty settings", List.of()));
            }
            lastClient = new TrackingClient(validationMode());
            return lastClient;
        }
    }

    public static final class AlternativeProvider extends FixtureProvider {
    }

    public static final class PrivateConstructorProvider extends FixtureProvider {
        private PrivateConstructorProvider() {
        }
    }

    public static class WrongModeProvider extends FixtureProvider {
        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) {
            lastClient = new TrackingClient(CAADNSClient.ValidationMode.DELEGATED_ENFORCING);
            return lastClient;
        }
    }

    public static final class MissingBehaviorProvider extends FixtureProvider {
        @Override
        public CAADNSClient.ValidationMode validationMode() {
            return null;
        }
    }

    public static final class NullClientProvider extends FixtureProvider {
        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) {
            return null;
        }
    }

    public static final class MissingLibraryProvider extends FixtureProvider {
        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) {
            throw new NoClassDefFoundError("private resolver configuration");
        }
    }

    public static final class FailingProvider extends FixtureProvider {
        private static DNSLookupException failure;

        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) throws DNSLookupException {
            throw failure;
        }
    }

    public static final class BrokenCleanupProvider extends WrongModeProvider {
        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) {
            CAADNSClient client = super.open(config);
            lastClient.failClose = true;
            return client;
        }
    }

    public static final class WrongSpiType {
        static { wrongTypeInitializations.incrementAndGet(); }
    }

    public static final class BrokenConstructorProvider extends FixtureProvider {
        public BrokenConstructorProvider() {
            throw new IllegalStateException("private resolver configuration");
        }
    }

    public static final class NullClientBehaviorProvider extends FixtureProvider {
        @Override public CAADNSClient open(Config config) {
            lastClient = new TrackingClient(null);
            return lastClient;
        }
    }

    public static final class LinkageCleanupProvider extends WrongModeProvider {
        @Override public CAADNSClient open(Config config) {
            var client = super.open(config);
            lastClient.failCloseLinkage = true;
            return client;
        }
    }

    /** In-memory result, with no network traffic or DNSSEC claim. */
    static final class TrackingClient implements CAADNSClient {
        final AtomicInteger closes = new AtomicInteger();
        final AtomicInteger lookups = new AtomicInteger();
        private final CAADNSClient.ValidationMode mode;
        boolean failClose;
        boolean failCloseLinkage;

        TrackingClient(CAADNSClient.ValidationMode mode) {
            this.mode = mode;
        }

        @Override
        public CAADNSClient.ValidationMode validationMode() {
            return mode;
        }

        @Override
        public CAADNSClient.LookupResult resolveCaa(DNSDomainName candidate, CAADNSClient.LookupBudget budget)
                throws DNSLookupException {
            budget.reserveQuery();
            lookups.incrementAndGet();
            return new CAADNSClient.LookupResult(candidate, candidate, CAADNSClient.LookupKind.RRSET,
                    List.of(new CAADNSClient.CAARecord(candidate, 30, 0, "issue",
                            "other.test".getBytes(StandardCharsets.US_ASCII))),
                    List.of(), List.of(new CAADNSClient.ResponseEvidence("in-memory-fixture", candidate,
                            0, false, CAADNSClient.DNSSECStatus.UNCHECKED, CAADNSClient.ValidationAssurance.NONE,
                            Instant.now(), "fixture", Optional.empty())), Optional.empty());
        }

        @Override
        public void close() {
            closes.incrementAndGet();
            if (failCloseLinkage) throw new NoClassDefFoundError("Fixture cleanup dependency disappeared");
            if (failClose) {
                throw new IllegalStateException("Fixture cleanup failed");
            }
        }
    }
}

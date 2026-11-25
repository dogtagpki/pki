// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests how CAA opens the DNS provider selected by instance configuration.
 * The loader connects the library-independent policy engine to an optional
 * adapter, while allowing core builds to omit that adapter and its library.
 * These tests focus on initialization failure and ownership of a successfully
 * opened client. Providers must establish DNSSEC enforcement during open().
 * Local test providers exercise loading without contacting a DNS server.
 */
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

    /**
     * Load two provider class names into the same real policy engine. Each
     * fixture denies issuance, records one lookup and is closed by the validator.
     */
    @Test
    void substitutesProviderClassesWithoutChangingTheEngine() throws Exception {
        for (Class<?> type : List.of(TestDNSProvider.class, AlternativeProvider.class)) {
            CAADNSClient client = open(type);
            CAAPolicy policy = new CAAPolicy(Set.of("issuer.test"));

            try (DefaultCAAValidator validator = new DefaultCAAValidator(client, policy)) {
                CAARequest request = new CAARequest(List.of(new CAARequest.CertificateName(NAME, false)), Map.of());

                CAADecision decision = validator.validate(request);

                assertEquals(CAADecision.Outcome.DENY, decision.outcome());
                assertEquals(1, lastClient.lookups.get());
            }
            assertEquals(1, lastClient.closes.get());
        }
    }

    /**
     * Verify this core-only test classpath contains neither dnsjava nor its
     * adapter. Explicitly selecting the absent adapter must fail configuration.
     */
    @Test
    void acmeRunsWithoutOptionalAdapterOrDnsjavaInstalled() {
        assertThrows(ClassNotFoundException.class, () -> Class.forName("org.xbill.DNS.Message", false, LOADER));
        assertConfigurationFailure(() -> CAADNSClientLoader.open(
                "org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider", LOADER, config()));
        assertNull(lastClient);
    }

    /**
     * Pass missing class names, an absent class and String as the provider.
     * All must fail configuration without constructing a DNS client.
     */
    @Test
    void rejectsBlankMissingAndWrongTypeClasses() {
        for (String name : new String[] { null, "", " ", "not.installed.Provider", String.class.getName() }) {
            assertConfigurationFailure(() -> CAADNSClientLoader.open(name, LOADER, config()));
        }
        assertNull(lastClient);
    }

    /**
     * Select a provider with a private constructor. Reflective loading must
     * reject it before opening a client.
     */
    @Test
    void requiresPublicNoArgumentConstruction() {
        assertConfigurationFailure(() -> open(PrivateConstructorProvider.class));
        assertNull(lastClient);
    }

    /**
     * Select a provider whose open() returns null. Initialization must fail
     * rather than produce a usable validator without a DNS client.
     */
    @Test
    void rejectsNullClient() {
        assertConfigurationFailure(() -> open(NullClientProvider.class));
    }

    /**
     * Simulate an optional dependency missing when the provider opens.
     * Convert the linkage error into a configuration failure without another provider.
     */
    @Test
    void missingLibraryIsAConfigurationFailureWithNoFallback() {
        assertConfigurationFailure(() -> open(MissingLibraryProvider.class));
        assertNull(lastClient);
    }

    /**
     * Make open() throw a specific typed DNS failure. The loader must return
     * that same exception, preserving its category instead of substituting a fallback.
     */
    @Test
    void propagatesProviderFailureWithoutTryingAnAlternative() {
        DNSLookupException expected = new DNSLookupException(new DNSLookupException.Failure(
                DNSLookupException.Reason.UNREACHABLE, "Fixture unavailable", List.of()));
        FailingProvider.failure = expected;

        assertSame(expected, assertThrows(DNSLookupException.class, () -> open(FailingProvider.class)));
        assertNull(lastClient);
    }

    /**
     * Use a non-provider class with a static-initializer counter. Checking its
     * type must not initialize the class or execute that unrelated code.
     */
    @Test
    void rejectingTheWrongSpiTypeDoesNotRunItsStaticInitializer() {
        assertEquals(0, wrongTypeInitializations.get());
        // A class literal supplies its type without running its static block.
        assertConfigurationFailure(() -> open(WrongSpiType.class));
        assertEquals(0, wrongTypeInitializations.get());
    }

    /**
     * Make the provider constructor throw before open(). Report configuration
     * failure and verify that no client was allocated.
     */
    @Test
    void constructorFailureIsConfigurationFailureAndDoesNotOpenAClient() {
        assertConfigurationFailure(() -> open(BrokenConstructorProvider.class));
        assertNull(lastClient);
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

    /**
     * Public no-argument construction follows the configured-component style.
     */
    public static class TestDNSProvider implements CAADNSClientProvider {

        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) throws DNSLookupException {
            if (!config.settings().isEmpty()) {
                throw new DNSLookupException(new DNSLookupException.Failure(DNSLookupException.Reason.CONFIGURATION,
                        "Fixture supports only empty settings", List.of()));
            }
            lastClient = new TrackingClient();
            return lastClient;
        }
    }

    /**
     * A second selectable provider class with the same behavior as TestDNSProvider.
     */
    public static final class AlternativeProvider extends TestDNSProvider {
    }

    /**
     * Cannot be constructed through the public no-argument provider contract.
     */
    public static final class PrivateConstructorProvider extends TestDNSProvider {
        private PrivateConstructorProvider() {
        }
    }

    /**
     * Returns no client from open().
     */
    public static final class NullClientProvider extends TestDNSProvider {

        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) {
            return null;
        }
    }

    /**
     * Simulates a missing optional dependency while opening a provider.
     */
    public static final class MissingLibraryProvider extends TestDNSProvider {

        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) {
            throw new NoClassDefFoundError("private resolver configuration");
        }
    }

    /**
     * Throws the exact typed failure assigned by the test.
     */
    public static final class FailingProvider extends TestDNSProvider {
        private static DNSLookupException failure;

        @Override
        public CAADNSClient open(CAADNSClientProvider.Config config) throws DNSLookupException {
            throw failure;
        }
    }

    /**
     * Does not implement the provider interface; initialization would change a counter.
     */
    public static final class WrongSpiType {
        static {
            wrongTypeInitializations.incrementAndGet();
        }
    }

    /**
     * Throws from construction before a client can be opened.
     */
    public static final class BrokenConstructorProvider extends TestDNSProvider {
        public BrokenConstructorProvider() {
            throw new IllegalStateException("private resolver configuration");
        }
    }

    /**
     * In-memory result modeling trusted delegation, without real DNS traffic.
     */
    static final class TrackingClient implements CAADNSClient {
        final AtomicInteger closes = new AtomicInteger();
        final AtomicInteger lookups = new AtomicInteger();
        @Override
        public CAADNSClient.LookupResult resolveCaa(DNSDomainName candidate, CAADNSClient.LookupBudget budget)
                throws DNSLookupException {
            budget.reserveQuery();
            lookups.incrementAndGet();
            CAADNSClient.CAARecord record = new CAADNSClient.CAARecord(
                    candidate, 30, 0, "issue", "other.test".getBytes(StandardCharsets.US_ASCII));
            CAADNSClient.ResponseEvidence response = new CAADNSClient.ResponseEvidence(
                    "in-memory-fixture", candidate, 0, false, CAADNSClient.ValidationStatus.UNCLASSIFIED, "fixture", Optional.empty());
            return new CAADNSClient.LookupResult(candidate, candidate, CAADNSClient.LookupKind.RRSET,
                    List.of(record), List.of(), List.of(response), Optional.empty());
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }
    }
}

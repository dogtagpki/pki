// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.util.List;
import java.util.Objects;

/**
 * Opens a DNS adapter selected by trusted subsystem configuration. This keeps
 * optional adapter and DNS-library classes out of the core's compile-time
 * dependencies while allowing the host to choose an installed implementation.
 *
 * The gate passes dns.class, its class loader and the extracted dns.settings.*
 * values to open(). The loader reads no configuration files and discovers no
 * alternative providers. The selected class must implement CAADNSClientProvider
 * and have a public no-argument constructor.
 *
 * Loading verifies the provider type before initialization, constructs it and
 * opens a client. The provider must establish the trusted DNSSEC deployment
 * required by CAADNSClient and release partial allocations if open() fails.
 * A declaration or class name alone cannot prove that a resolver is enforcing
 * validation. A failure is returned to the host without trying another provider.
 *
 * After success the caller owns the client, normally through a validator and
 * gate. The host calls this loader only when CAA is enabled, so disabled hosts
 * need no optional adapter installed. Provider selection is privileged host
 * configuration and must never come from enrollment input.
 */
public final class CAADNSClientLoader {

    private CAADNSClientLoader() {
    }

    /**
     * Opens a client required to enforce trusted DNSSEC validation. The host
     * owns the returned client. Closing it must be safe alongside active lookups and cancel
     * waiting callers; library transport cleanup follows the client contract.
     * Call only when CAA is enabled; disabled hosts need no adapter installed.
     * Provider code runs with host privileges and is never enrollment input.
     */
    public static CAADNSClient open(String className, ClassLoader loader,
            CAADNSClientProvider.Config config) throws DNSLookupException {
        Objects.requireNonNull(loader);
        Objects.requireNonNull(config);
        if (className == null || className.isBlank()) {
            throw configurationFailure("No CAA DNS provider class configured", null);
        }

        try {
            // Resolve the type without running its static initializer. Check
            // the SPI first; construction then initializes the selected provider.
            Class<? extends CAADNSClientProvider> providerClass = Class.forName(className, false, loader)
                    .asSubclass(CAADNSClientProvider.class);
            CAADNSClientProvider provider = providerClass.getDeclaredConstructor().newInstance();
            return Objects.requireNonNull(provider.open(config), "Provider returned no client");

        } catch (DNSLookupException e) {
            throw e;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            throw configurationFailure("Unable to initialize CAA DNS provider", e);
        }
    }

    private static DNSLookupException configurationFailure(String message, Throwable cause) {
        DNSLookupException failure = new DNSLookupException(new DNSLookupException.Failure(
                DNSLookupException.Reason.CONFIGURATION, message, List.of()));
        if (cause != null) {
            failure.initCause(cause);
        }

        return failure;
    }
}

// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.util.List;
import java.util.Objects;

/**
 * Loads one installed DNS provider selected by trusted subsystem configuration.
 */
public final class CAADNSClientLoader {

    private CAADNSClientLoader() {
    }

    /**
     * Opens a client with fixed provider behavior. The host owns the returned
     * client. Closing it must be safe alongside active lookups and cancel
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

        CAADNSClient client = null;
        try {
            // Resolve the type without running its static initializer. Check
            // the SPI first; construction then initializes the selected provider.
            Class<? extends CAADNSClientProvider> providerClass = Class.forName(className, false, loader)
                    .asSubclass(CAADNSClientProvider.class);
            CAADNSClientProvider provider = providerClass.getDeclaredConstructor().newInstance();
            CAADNSClient.ValidationMode behavior = Objects.requireNonNull(provider.validationMode(),
                    "Provider did not declare its fixed behavior");
            client = Objects.requireNonNull(provider.open(config), "Provider returned no client");
            if (client.validationMode() != behavior) {
                throw configurationFailure("DNS client differs from its provider behavior", null);
            }

            return client;

        } catch (DNSLookupException e) {
            closeAfterFailure(client, e);
            throw e;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            DNSLookupException failure = configurationFailure("Unable to initialize CAA DNS provider", e);
            closeAfterFailure(client, failure);
            throw failure;
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

    private static void closeAfterFailure(CAADNSClient client, DNSLookupException failure) {
        if (client != null) {
            try {
                client.close();
            } catch (RuntimeException | LinkageError e) {
                failure.addSuppressed(e);
            }
        }
    }
}

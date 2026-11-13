// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.util.Map;

/**
 * Initializes an installed DNS adapter selected by trusted class-name configuration.
 * Implementations have a public no-argument constructor; initialization belongs
 * in open(), which must clean up its resources if it cannot return a client.
 * DNS adapters belong in optional modules outside the ACME core artifact, so
 * the shared policy engine has no dependency on a particular DNS library.
 */
public interface CAADNSClientProvider {
    /**
     * Fixed behavior of this implementation, not a configuration option.
     */
    CAADNSClient.ValidationMode validationMode();

    /**
     * Creates a concurrently usable client owned by the consuming subsystem,
     * or throws a typed initialization failure. Class selection and settings
     * come from trusted administrator configuration, never enrollment input.
     * Opening a provider must not add a hidden fallback to weaker validation.
     */
    CAADNSClient open(Config config) throws DNSLookupException;

    /**
     * Carries administrator-controlled DNS adapter configuration.
     */
    public record Config(Map<String, String> settings) {
        public Config {
            settings = Map.copyOf(settings);
        }

        @Override
        public String toString() {
            return "Config[settings=<redacted>]";
        }
    }
}

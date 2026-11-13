// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.util.Map;

/**
 * Factory contract for optional DNS adapters. A configured provider opens the
 * long-lived CAADNSClient used by the library-independent CAA engine.
 *
 * Initialization:
 * - The host supplies trusted settings to CAADNSClientLoader. The loader creates
 *   the selected provider through its public no-argument constructor and calls
 *   open(); resource initialization belongs in open(), not the constructor.
 * - Every returned client must enforce the CAADNSClient DNSSEC contract.
 *   open() must reject unsupported resolver settings and establish the
 *   trusted validation deployment before returning a usable client.
 * - The provider validates its settings and cleans up partial allocations if
 *   initialization fails. After success, the returned client is owned through
 *   the validator's lifecycle. The provider itself is not a per-request client.
 *
 * The gate maps dns.class to the provider's binary class name and strips the
 * dns.settings. prefix before passing settings here. For example,
 * dns.settings.server becomes Config.settings().get("server"). File locations
 * and property loading belong to the host; this interface reads no files itself.
 * Adapters live in optional modules so core builds need no particular DNS library.
 */
public interface CAADNSClientProvider {
    /**
     * Creates a concurrently usable client owned by the consuming subsystem,
     * or throws a typed initialization failure. Class selection and settings
     * come from trusted administrator configuration, never enrollment input.
     */
    CAADNSClient open(Config config) throws DNSLookupException;

    /**
     * Immutable snapshot of administrator-controlled, adapter-specific settings.
     * Keys arrive without the host's dns.settings. prefix. The selected provider
     * validates supported keys, values and required settings. Its configuration is
     * fixed for the returned client's lifetime; changes require replacement.
     * The string representation omits settings to avoid incidental disclosure.
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

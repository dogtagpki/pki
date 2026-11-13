// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Carries the final intended DNS names and verified per-name binding facts.
 * The host extracts names from its issuance data and preserves wildcard status;
 * this type has no dependency on a CSR, certificate template or ACME order.
 * Contexts may be empty. A grant requiring unavailable binding facts cannot
 * authorize issuance, although another applicable grant may authorize it.
 */
public record CAARequest(
        List<CertificateName> names,
        Map<CertificateName, IssuanceContext> contexts) {
    public CAARequest {
        names = List.copyOf(names);
        contexts = Map.copyOf(contexts);
        if (names.isEmpty() || new HashSet<>(names).size() != names.size()) {
            throw new IllegalArgumentException("Expected nonempty, distinct certificate names");
        }

        if (!names.containsAll(contexts.keySet())) {
            throw new IllegalArgumentException("Context must identify a requested name");
        }
    }

    /**
     * Identifies a certificate DNS name and its wildcard status.
     */
    public record CertificateName(DNSDomainName baseName, boolean wildcard) {
        public CertificateName {
            Objects.requireNonNull(baseName);
            if (baseName.asciiAbsoluteName().equals(".") || baseName.asciiAbsoluteName().contains("_")) {
                throw new IllegalArgumentException("Expected certificate DNS name");
            }
        }
    }

    /**
     * Carries account and validation-method facts verified by the consuming host.
     * Constructor checks validate syntax only, not account ownership or challenge success.
     */
    public record IssuanceContext(
            Optional<URI> accountUri,
            Optional<String> validationMethod) {
        public IssuanceContext {
            Objects.requireNonNull(accountUri);
            Objects.requireNonNull(validationMethod);
            if (accountUri.isPresent() && !accountUri.get().isAbsolute()) {
                throw new IllegalArgumentException("Account URI must be absolute");
            }

            if (validationMethod.isPresent() && !validationMethod.get().matches("[A-Za-z0-9-]+")) {
                throw new IllegalArgumentException("Invalid validation method label");
            }
        }
    }
}

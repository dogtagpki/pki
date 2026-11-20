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
 * Supplies the certificate identities and trusted binding facts for one CAA
 * validation attempt, independently of a CSR, certificate template or ACME order.
 * The host extracts final intended names from its issuance data and selects the
 * applicable issuer policy separately when constructing the validator.
 *
 * Inputs:
 * - names must be nonempty and distinct. An ordinary and wildcard name may have
 *   the same DNS base name; they are separate certificate identities.
 * - contexts optionally maps each requested identity to verified account/method
 *   facts. It cannot attach context to a name absent from the request.
 * - Collections are copied so later caller changes do not alter the attempt.
 *
 * For example, a wildcard for *.customer.example may be represented as:
 *   CertificateName name = new CertificateName(
 *           new DNSDomainName("customer.example."), true);
 *   IssuanceContext context = new IssuanceContext(
 *           Optional.of(URI.create("https://acme.example/acct/1234")),
 *           Optional.of("dns-01"));
 *   CAARequest request = new CAARequest(List.of(name), Map.of(name, context));
 *
 * The host, not this record, establishes the trustworthiness of that context.
 * Missing context cannot satisfy a grant requiring it; another applicable grant
 * without those restrictions may still authorize issuance. The host must ensure
 * that later certificate processing preserves the checked identities.
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
     * Identifies one DNS name being certified. baseName is an absolute ASCII name
     * without a wildcard prefix; wildcard records whether the certificate identity
     * has that prefix. For *.customer.example, use customer.example. and true.
     * The host performs any required IDNA conversion before construction. DNS root
     * and underscore labels are rejected for certificate identities.
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
     * Carries facts used to evaluate accounturi and validationmethods restrictions.
     * For ACME, the host obtains the account URI and successful validation method
     * for this name from trusted account/authorization state. Other consumers must
     * provide equivalent verified facts using their defined account/method mapping.
     *
     * Both fields are optional. An absent fact makes a grant requiring it unusable;
     * it does not turn off binding enforcement. The engine compares account URIs
     * as exact strings and requires the supplied method to appear in the grant's
     * method list. These constructor checks validate syntax only: they do not
     * prove account ownership, authenticate a caller or perform domain validation.
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

// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashSet;
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
 * - names must contain 1 to 128 distinct identities. An ordinary and wildcard
 *   name may share a DNS base name; they are separate certificate identities.
 * - contexts optionally maps each requested identity to verified account/method
 *   facts. It cannot attach context to a name absent from the request.
 * - Collections are copied so later caller changes do not alter the attempt.
 *
 * The host establishes the trustworthiness of the binding context.
 * Missing context cannot satisfy a grant requiring it; another applicable grant
 * without those restrictions may still authorize issuance. The host must ensure
 * that later certificate processing preserves the checked identities.
 *
 * For example, a wildcard for *.customer.example may be represented as:
 *   CertificateName name = new CertificateName(
 *           new DNSDomainName("customer.example."), true);
 *   IssuanceContext context = new IssuanceContext(
 *           Optional.of(URI.create("https://acme.example/acct/1234")),
 *           Optional.of("dns-01"));
 *   CAARequest request = new CAARequest(List.of(name), Map.of(name, context));
 */
public record CAARequest(
        List<CertificateName> names,
        Map<CertificateName, IssuanceContext> contexts) {
    // Bound per-name reporting even when admission fails or the deadline expires.
    // This matches the fixed client-query allowance, without promising that every
    // request at the limit can finish within the other discovery/resource limits.
    public static final int MAX_NAMES = 128;

    public CAARequest {
        Objects.requireNonNull(names);
        Objects.requireNonNull(contexts);
        int count = names.size();
        if (count == 0 || count > MAX_NAMES || contexts.size() > count) {
            throw new IllegalArgumentException("Expected 1 to " + MAX_NAMES + " certificate names and matching contexts");
        }

        // The caller may change either collection after the size check. Bound
        // traversal itself and validate the entries we actually captured.
        var distinctNames = new LinkedHashSet<CertificateName>();
        for (CertificateName name : names) {
            if (distinctNames.size() == MAX_NAMES || !distinctNames.add(Objects.requireNonNull(name))) {
                throw new IllegalArgumentException("Too many or duplicate certificate names");
            }
        }
        if (distinctNames.isEmpty()) {
            throw new IllegalArgumentException("Missing certificate names");
        }
        names = List.copyOf(distinctNames);

        var bindings = new HashMap<CertificateName, IssuanceContext>();
        for (var entry : contexts.entrySet()) {
            CertificateName name = entry.getKey();
            if (!distinctNames.contains(name)) {
                throw new IllegalArgumentException("Context must identify a requested name");
            }
            if (bindings.putIfAbsent(name, Objects.requireNonNull(entry.getValue())) != null) {
                throw new IllegalArgumentException("Duplicate context for certificate name");
            }
        }
        contexts = Map.copyOf(bindings);
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
            // The wildcard label adds two octets to the complete wire name.
            if (wildcard && baseName.asciiAbsoluteName().length() > 252) {
                throw new IllegalArgumentException("Wildcard certificate DNS name is too long");
            }
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

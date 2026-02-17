//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.security.cert.X509Certificate;

import com.netscape.cms.realm.PKIPrincipalCore;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.CertificateAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/**
 * Shared Quarkus identity provider for PKI certificate authentication.
 *
 * This is a base identity provider that validates X.509 certificates.
 * Subsystem-specific modules should extend this class and provide
 * a PKIAuthenticator instance for real LDAP-backed user lookup.
 *
 * This base implementation performs basic certificate validation only.
 * Override authenticateCertificate() for full PKI authentication.
 */
public class PKIIdentityProvider implements IdentityProvider<CertificateAuthenticationRequest> {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIIdentityProvider.class);

    @Override
    public Class<CertificateAuthenticationRequest> getRequestType() {
        return CertificateAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(CertificateAuthenticationRequest request,
            AuthenticationRequestContext context) {

        return context.runBlocking(() -> {
            X509Certificate cert = request.getCertificate().getCertificate();

            try {
                cert.checkValidity();
            } catch (Exception e) {
                logger.warn("PKIIdentityProvider: Certificate validation failed: {}", e.getMessage());
                throw new AuthenticationFailedException("Certificate validation failed", e);
            }

            PKIPrincipalCore principal = authenticateCertificate(cert);
            if (principal == null) {
                throw new AuthenticationFailedException("Certificate authentication failed");
            }

            QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(principal.getName()))
                    .addCredential(request.getCertificate());

            for (String role : principal.getRoles()) {
                builder.addRole(role);
            }

            // Store the PKIPrincipalCore as an attribute for downstream access
            builder.addAttribute("pki.principal", principal);

            return (SecurityIdentity) builder.build();
        });
    }

    /**
     * Authenticate a certificate and return a PKIPrincipalCore.
     *
     * Subclasses should override this to integrate with the real
     * PKI user database via PKIAuthenticator.
     *
     * @param cert the client certificate
     * @return a PKIPrincipalCore on success, or null on failure
     */
    protected PKIPrincipalCore authenticateCertificate(X509Certificate cert) {
        // Base implementation: extract principal name from certificate
        String dn = cert.getSubjectX500Principal().getName();
        String cn = extractCN(dn);
        String principalName = cn != null ? cn : dn;

        logger.info("PKIIdentityProvider: Authenticated certificate for: {}", principalName);

        return new PKIPrincipalCore(principalName, null, java.util.List.of("est-client"));
    }

    /**
     * Extract the CN (Common Name) from an X.500 Distinguished Name.
     */
    protected String extractCN(String dn) {
        if (dn == null) return null;
        for (String rdn : dn.split(",")) {
            String trimmed = rdn.trim();
            if (trimmed.toUpperCase().startsWith("CN=")) {
                return trimmed.substring(3).trim();
            }
        }
        return null;
    }
}

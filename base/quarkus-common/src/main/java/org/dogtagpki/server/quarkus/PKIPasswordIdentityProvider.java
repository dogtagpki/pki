//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import com.netscape.cms.realm.PKIPrincipalCore;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/**
 * Shared Quarkus identity provider for PKI password authentication.
 *
 * This is a base identity provider for username/password authentication.
 * Subsystem-specific modules should extend this class and provide
 * a PKIAuthenticator instance for real LDAP-backed user lookup.
 */
public class PKIPasswordIdentityProvider implements IdentityProvider<UsernamePasswordAuthenticationRequest> {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(
            PKIPasswordIdentityProvider.class);

    @Override
    public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
        return UsernamePasswordAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
            AuthenticationRequestContext context) {

        return context.runBlocking(() -> {
            String username = request.getUsername();
            String password = new String(request.getPassword().getPassword());

            PKIPrincipalCore principal = authenticateByPassword(username, password);
            if (principal == null) {
                throw new AuthenticationFailedException("Invalid username or password");
            }

            QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(principal.getName()));

            for (String role : principal.getRoles()) {
                builder.addRole(role);
            }

            builder.addAttribute("pki.principal", principal);

            return (SecurityIdentity) builder.build();
        });
    }

    /**
     * Authenticate by username and password.
     *
     * Subclasses should override this to integrate with the real
     * PKI user database via PKIAuthenticator.
     *
     * @param username the username
     * @param password the password
     * @return a PKIPrincipalCore on success, or null on failure
     */
    protected PKIPrincipalCore authenticateByPassword(String username, String password) {
        logger.warn("PKIPasswordIdentityProvider: Base implementation called - override for real authentication");
        return null;
    }
}

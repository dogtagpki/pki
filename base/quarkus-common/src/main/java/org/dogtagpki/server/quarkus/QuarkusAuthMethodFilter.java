//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.security.Principal;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;

import com.netscape.cms.realm.PKIPrincipalCore;

/**
 * Quarkus ContainerRequestFilter for authentication method checking.
 *
 * Subsystem-specific modules should extend this class and provide
 * the auth method name and AuthMethodChecker instance.
 */
public abstract class QuarkusAuthMethodFilter implements ContainerRequestFilter {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(QuarkusAuthMethodFilter.class);

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String method = requestContext.getMethod();
        String path = requestContext.getUriInfo().getPath();
        String authMethodName = getAuthMethodName(method, path);

        logger.debug("QuarkusAuthMethodFilter: Checking auth method {} for {}:{}", authMethodName, method, path);

        Principal principal = requestContext.getSecurityContext().getUserPrincipal();

        PKIPrincipalCore pkiPrincipal = extractPKIPrincipal(requestContext);

        checkAuthMethod(pkiPrincipal != null ? pkiPrincipal : principal, authMethodName);
    }

    /**
     * Get the auth method name for the given method and path.
     * Subclasses should implement this based on their auth method mapping.
     */
    protected abstract String getAuthMethodName(String method, String path);

    /**
     * Perform the auth method check. Subclasses should implement this
     * using their AuthMethodChecker instance.
     */
    protected abstract void checkAuthMethod(Principal principal, String authMethodName);

    /**
     * Extract PKIPrincipalCore from the request context if available.
     */
    protected PKIPrincipalCore extractPKIPrincipal(ContainerRequestContext requestContext) {
        return null;
    }
}

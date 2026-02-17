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
 * Quarkus ContainerRequestFilter for ACL checking.
 *
 * Subsystem-specific modules should extend this class and provide
 * the ACL name and engine reference for real ACL evaluation.
 *
 * This is a base class that subsystems extend to integrate with
 * their ACLChecker instance.
 */
public abstract class QuarkusACLFilter implements ContainerRequestFilter {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(QuarkusACLFilter.class);

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String method = requestContext.getMethod();
        String path = requestContext.getUriInfo().getPath();
        String aclName = getACLName(method, path);

        logger.debug("QuarkusACLFilter: Checking ACL {} for {}:{}", aclName, method, path);

        Principal principal = requestContext.getSecurityContext().getUserPrincipal();

        // Convert Quarkus SecurityIdentity principal to PKIPrincipalCore if available
        PKIPrincipalCore pkiPrincipal = extractPKIPrincipal(requestContext);

        checkACL(pkiPrincipal != null ? pkiPrincipal : principal, method, path, aclName);
    }

    /**
     * Get the ACL name for the given method and path.
     * Subclasses should implement this based on their ACL mapping.
     */
    protected abstract String getACLName(String method, String path);

    /**
     * Perform the ACL check. Subclasses should implement this
     * using their ACLChecker instance.
     */
    protected abstract void checkACL(Principal principal, String method, String path, String aclName);

    /**
     * Extract PKIPrincipalCore from the request context if available.
     */
    protected PKIPrincipalCore extractPKIPrincipal(ContainerRequestContext requestContext) {
        // Subclasses can override to extract from SecurityIdentity attributes
        return null;
    }
}

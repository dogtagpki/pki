//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.security.Principal;
import java.util.List;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;
import com.netscape.cms.realm.PKIPrincipalCore;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * ACME login endpoint.
 *
 * This is not part of the ACME protocol (RFC 8555) but provides
 * web UI authentication support.
 */
@Path("login")
public class ACMELoginResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMELoginResource.class);

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    SecurityContext securityContext;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getLogin() throws Exception {

        Principal principal = securityContext.getUserPrincipal();
        logger.info("ACMELoginResource: Principal: " + principal);

        if (principal == null) {
            return Response.noContent().build();
        }

        Account account = createAccount(principal);
        return Response.ok(account.toJSON()).build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response postLogin() throws Exception {

        Principal principal = securityContext.getUserPrincipal();
        logger.info("ACMELoginResource: Principal: " + principal);

        if (principal == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        Account account = createAccount(principal);
        return Response.ok(account.toJSON()).build();
    }

    protected Account createAccount(Principal principal) {

        String username = principal.getName();
        logger.info("ACMELoginResource: Principal: " + username);

        Account account = new Account();
        account.setID(username);

        // Check for PKIPrincipalCore stored as SecurityIdentity attribute
        PKIPrincipalCore pkiPrincipal = securityIdentity.getAttribute("pki.principal");
        if (pkiPrincipal != null) {
            Object user = pkiPrincipal.getUser();
            if (user != null) {
                // User details would be populated from the PKI user database
                logger.info("ACMELoginResource: PKI principal found for: " + username);
            }

            List<String> roles = pkiPrincipal.getRoles();
            if (roles != null) {
                logger.info("ACMELoginResource: Roles:");
                for (String role : roles) {
                    logger.info("ACMELoginResource: - " + role);
                }
                account.setRoles(roles);
            }
        }

        return account;
    }
}

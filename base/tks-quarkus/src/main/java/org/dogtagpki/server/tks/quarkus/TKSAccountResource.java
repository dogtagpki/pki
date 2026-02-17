//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import java.security.Principal;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.rest.base.AccountServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;

/**
 * JAX-RS resource for TKS account operations.
 * Replaces TKSAccountServlet.
 */
@Path("v2/account")
public class TKSAccountResource {

    private static final Logger logger = LoggerFactory.getLogger(TKSAccountResource.class);

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Context
    SecurityContext securityContext;

    @GET
    @Path("login")
    @Produces(MediaType.APPLICATION_JSON)
    public Response login() throws Exception {
        Principal principal = securityContext.getUserPrincipal();
        logger.info("TKSAccountResource: Login for principal: {}", principal != null ? principal.getName() : "null");

        Account account = AccountServletBase.createAccount(principal);
        return Response.ok(account.toJSON()).build();
    }

    @GET
    @Path("logout")
    public Response logout() {
        logger.info("TKSAccountResource: Logout (stateless, no-op)");
        return Response.noContent().build();
    }
}

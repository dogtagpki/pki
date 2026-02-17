//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.security.Principal;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
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
 * JAX-RS resource for KRA account operations.
 * Replaces KRAAccountServlet.
 */
@Path("v2/account")
public class KRAAccountResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAAccountResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Context
    SecurityContext securityContext;

    @GET
    @Path("login")
    @Produces(MediaType.APPLICATION_JSON)
    public Response login() throws Exception {
        logger.debug("KRAAccountResource.login()");
        Principal principal = securityContext.getUserPrincipal();
        AccountServletBase base = new AccountServletBase(engineQuarkus.getEngine());
        Account account = base.createAccount(principal);
        return Response.ok(account.toJSON()).build();
    }

    @GET
    @Path("logout")
    public Response logout() throws Exception {
        logger.debug("KRAAccountResource.logout()");
        // Stateless - no session to invalidate
        return Response.noContent().build();
    }

    @POST
    @Path("logout")
    public Response logoutPost() throws Exception {
        return logout();
    }
}

//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.common.AccountInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for CA account operations.
 * Replaces CAAccountServlet.
 */
@Path("v2/account")
public class CAAccountResource {

    private static final Logger logger = LoggerFactory.getLogger(CAAccountResource.class);

    @Inject
    SecurityIdentity identity;

    @GET
    @Path("login")
    @Produces(MediaType.APPLICATION_JSON)
    public Response login() {
        logger.debug("CAAccountResource.login()");
        AccountInfo accountInfo = new AccountInfo();
        accountInfo.setID(identity.getPrincipal().getName());
        accountInfo.setRoles(new java.util.ArrayList<>(identity.getRoles()));
        return Response.ok(accountInfo.toJSON()).build();
    }

    @GET
    @Path("logout")
    @Produces(MediaType.APPLICATION_JSON)
    public Response logout() {
        logger.debug("CAAccountResource.logout()");
        return Response.noContent().build();
    }
}

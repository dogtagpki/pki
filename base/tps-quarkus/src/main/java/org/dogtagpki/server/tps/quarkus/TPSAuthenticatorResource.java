//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.net.URLEncoder;
import java.security.Principal;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.rest.base.AuthenticatorProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.tps.authenticator.AuthenticatorCollection;
import com.netscape.certsrv.tps.authenticator.AuthenticatorData;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for TPS authenticator operations.
 * Replaces AuthenticatorServlet.
 */
@Path("v2/authenticators")
public class TPSAuthenticatorResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSAuthenticatorResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @Context
    UriInfo uriInfo;

    private AuthenticatorProcessor createProcessor() {
        return new AuthenticatorProcessor(engineQuarkus.getEngine());
    }

    private Principal getPrincipal() {
        return TPSEngineQuarkus.toPKIPrincipal(identity);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findAuthenticators(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSAuthenticatorResource.findAuthenticators()");
        AuthenticatorCollection authenticators = createProcessor().findAuthenticators(filter, start, size);
        return Response.ok(authenticators.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addAuthenticator(String requestData) throws Exception {
        logger.debug("TPSAuthenticatorResource.addAuthenticator()");
        AuthenticatorData data = JSONSerializer.fromJSON(requestData, AuthenticatorData.class);
        AuthenticatorData authenticator = createProcessor().addAuthenticator(getPrincipal(), data);
        String encodedID = URLEncoder.encode(authenticator.getID(), "UTF-8");
        java.net.URI location = uriInfo.getAbsolutePathBuilder().path(encodedID).build();
        return Response.created(location).entity(authenticator.toJSON()).build();
    }

    @GET
    @Path("{authenticatorId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthenticator(@PathParam("authenticatorId") String authenticatorId) throws Exception {
        logger.debug("TPSAuthenticatorResource.getAuthenticator(): id={}", authenticatorId);
        AuthenticatorData authenticator = createProcessor().getAuthenticator(authenticatorId);
        return Response.ok(authenticator.toJSON()).build();
    }

    @PATCH
    @Path("{authenticatorId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateAuthenticator(
            @PathParam("authenticatorId") String authenticatorId,
            String requestData) throws Exception {
        logger.debug("TPSAuthenticatorResource.updateAuthenticator(): id={}", authenticatorId);
        AuthenticatorData data = JSONSerializer.fromJSON(requestData, AuthenticatorData.class);
        AuthenticatorData authenticator = createProcessor().updateAuthenticator(getPrincipal(), authenticatorId, data);
        return Response.ok(authenticator.toJSON()).build();
    }

    @POST
    @Path("{authenticatorId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeStatus(
            @PathParam("authenticatorId") String authenticatorId,
            @QueryParam("action") String action) throws Exception {
        logger.debug("TPSAuthenticatorResource.changeStatus(): id={}, action={}", authenticatorId, action);
        AuthenticatorData authenticator = createProcessor().changeStatus(getPrincipal(), authenticatorId, action);
        return Response.ok(authenticator.toJSON()).build();
    }

    @DELETE
    @Path("{authenticatorId}")
    public Response removeAuthenticator(@PathParam("authenticatorId") String authenticatorId) throws Exception {
        logger.debug("TPSAuthenticatorResource.removeAuthenticator(): id={}", authenticatorId);
        createProcessor().removeAuthenticator(getPrincipal(), authenticatorId);
        return Response.noContent().build();
    }
}

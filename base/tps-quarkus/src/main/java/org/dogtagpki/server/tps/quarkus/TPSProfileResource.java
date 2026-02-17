//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.net.URLEncoder;
import java.security.Principal;
import java.util.List;

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

import org.dogtagpki.server.tps.rest.base.ProfileProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.tps.profile.ProfileCollection;
import com.netscape.certsrv.tps.profile.ProfileData;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for TPS profile operations.
 * Replaces TPSProfileServlet.
 *
 * Profile operations use authorization-aware methods that
 * filter results based on the user's authorized TPS profiles.
 */
@Path("v2/profiles")
public class TPSProfileResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSProfileResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @Context
    UriInfo uriInfo;

    private ProfileProcessor createProcessor() {
        return new ProfileProcessor(engineQuarkus.getEngine());
    }

    private Principal getPrincipal() {
        return TPSEngineQuarkus.toPKIPrincipal(identity);
    }

    private List<String> getAuthorizedProfiles() {
        return TPSEngineQuarkus.getAuthorizedProfiles(identity);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findProfiles(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSProfileResource.findProfiles()");
        ProfileCollection profiles = createProcessor().findProfiles(getAuthorizedProfiles(), filter, start, size);
        return Response.ok(profiles.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addProfile(String requestData) throws Exception {
        logger.debug("TPSProfileResource.addProfile()");
        ProfileData data = JSONSerializer.fromJSON(requestData, ProfileData.class);
        ProfileData profile = createProcessor().addProfile(getPrincipal(), data);
        String encodedID = URLEncoder.encode(profile.getID(), "UTF-8");
        java.net.URI location = uriInfo.getAbsolutePathBuilder().path(encodedID).build();
        return Response.created(location).entity(profile.toJSON()).build();
    }

    @GET
    @Path("{profileId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getProfile(@PathParam("profileId") String profileId) throws Exception {
        logger.debug("TPSProfileResource.getProfile(): id={}", profileId);
        ProfileData profile = createProcessor().getProfile(getAuthorizedProfiles(), profileId);
        return Response.ok(profile.toJSON()).build();
    }

    @PATCH
    @Path("{profileId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateProfile(
            @PathParam("profileId") String profileId,
            String requestData) throws Exception {
        logger.debug("TPSProfileResource.updateProfile(): id={}", profileId);
        ProfileData data = JSONSerializer.fromJSON(requestData, ProfileData.class);
        ProfileData profile = createProcessor().updateProfile(getPrincipal(), getAuthorizedProfiles(), profileId, data);
        return Response.ok(profile.toJSON()).build();
    }

    @POST
    @Path("{profileId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeStatus(
            @PathParam("profileId") String profileId,
            @QueryParam("action") String action) throws Exception {
        logger.debug("TPSProfileResource.changeStatus(): id={}, action={}", profileId, action);
        ProfileData profile = createProcessor().changeStatus(getPrincipal(), getAuthorizedProfiles(), profileId, action);
        return Response.ok(profile.toJSON()).build();
    }

    @DELETE
    @Path("{profileId}")
    public Response removeProfile(@PathParam("profileId") String profileId) throws Exception {
        logger.debug("TPSProfileResource.removeProfile(): id={}", profileId);
        createProcessor().removeProfile(getPrincipal(), profileId);
        return Response.noContent().build();
    }
}

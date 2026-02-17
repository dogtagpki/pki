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

import org.dogtagpki.server.tps.rest.base.ProfileMappingProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.tps.profile.ProfileMappingCollection;
import com.netscape.certsrv.tps.profile.ProfileMappingData;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for TPS profile mapping operations.
 * Replaces ProfileMappingServlet.
 */
@Path("v2/profile-mappings")
public class TPSProfileMappingResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSProfileMappingResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @Context
    UriInfo uriInfo;

    private ProfileMappingProcessor createProcessor() {
        return new ProfileMappingProcessor(engineQuarkus.getEngine());
    }

    private Principal getPrincipal() {
        return TPSEngineQuarkus.toPKIPrincipal(identity);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findProfileMappings(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("pageSize") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSProfileMappingResource.findProfileMappings()");
        ProfileMappingCollection mappings = createProcessor().findProfileMappings(filter, start, size);
        return Response.ok(mappings.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addProfileMapping(String requestData) throws Exception {
        logger.debug("TPSProfileMappingResource.addProfileMapping()");
        ProfileMappingData data = JSONSerializer.fromJSON(requestData, ProfileMappingData.class);
        ProfileMappingData mapping = createProcessor().addProfileMapping(getPrincipal(), data);
        String encodedID = URLEncoder.encode(mapping.getID(), "UTF-8");
        java.net.URI location = uriInfo.getAbsolutePathBuilder().path(encodedID).build();
        return Response.created(location).entity(mapping.toJSON()).build();
    }

    @GET
    @Path("{mappingId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getProfileMapping(@PathParam("mappingId") String mappingId) throws Exception {
        logger.debug("TPSProfileMappingResource.getProfileMapping(): id={}", mappingId);
        ProfileMappingData mapping = createProcessor().getProfileMapping(mappingId);
        return Response.ok(mapping.toJSON()).build();
    }

    @PATCH
    @Path("{mappingId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateProfileMapping(
            @PathParam("mappingId") String mappingId,
            String requestData) throws Exception {
        logger.debug("TPSProfileMappingResource.updateProfileMapping(): id={}", mappingId);
        ProfileMappingData data = JSONSerializer.fromJSON(requestData, ProfileMappingData.class);
        ProfileMappingData mapping = createProcessor().updateProfileMapping(getPrincipal(), mappingId, data);
        return Response.ok(mapping.toJSON()).build();
    }

    @POST
    @Path("{mappingId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeStatus(
            @PathParam("mappingId") String mappingId,
            @QueryParam("action") String action) throws Exception {
        logger.debug("TPSProfileMappingResource.changeStatus(): id={}, action={}", mappingId, action);
        ProfileMappingData mapping = createProcessor().changeStatus(getPrincipal(), mappingId, action);
        return Response.ok(mapping.toJSON()).build();
    }

    @DELETE
    @Path("{mappingId}")
    public Response removeProfileMapping(@PathParam("mappingId") String mappingId) throws Exception {
        logger.debug("TPSProfileMappingResource.removeProfileMapping(): id={}", mappingId);
        createProcessor().removeProfileMapping(getPrincipal(), mappingId);
        return Response.noContent().build();
    }
}

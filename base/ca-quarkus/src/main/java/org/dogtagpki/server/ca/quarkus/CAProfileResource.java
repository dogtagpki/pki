//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.InputStream;
import java.net.URLEncoder;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.rest.base.ProfileBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for CA profile operations.
 * Replaces ProfileServlet.
 */
@Path("v2/profiles")
public class CAProfileResource {

    private static final Logger logger = LoggerFactory.getLogger(CAProfileResource.class);
    private static final int DEFAULT_SIZE = 20;

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    private ProfileBase getProfileBase() {
        return new ProfileBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listProfiles(
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size,
            @QueryParam("visible") Boolean visible,
            @QueryParam("enable") Boolean enable,
            @QueryParam("enableBy") String enableBy) throws Exception {

        ProfileDataInfos profiles = getProfileBase().listProfiles(null, start, size, visible, enable, enableBy);
        return Response.ok(profiles.toJSON()).build();
    }

    @GET
    @Path("{profileId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveProfile(@PathParam("profileId") String profileId) throws Exception {
        ProfileData profileData = getProfileBase().retrieveProfile(null, profileId);
        return Response.ok(profileData.toJSON()).build();
    }

    @GET
    @Path("{profileId}/raw")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response retrieveProfileRaw(@PathParam("profileId") String profileId) throws Exception {
        byte[] rawProfile = getProfileBase().retrieveRawProfile(null, profileId);
        return Response.ok(rawProfile).type(MediaType.APPLICATION_OCTET_STREAM).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createProfile(String requestData) throws Exception {
        ProfileData reqProfile = JSONSerializer.fromJSON(requestData, ProfileData.class);
        String newProfileId = getProfileBase().createProfile(null, reqProfile);
        ProfileData newProfile = getProfileBase().retrieveProfile(null, newProfileId);
        return Response.status(Response.Status.CREATED)
                .entity(newProfile.toJSON())
                .build();
    }

    @POST
    @Path("raw")
    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response createProfileRaw(byte[] data) throws Exception {
        String newProfileId = getProfileBase().createProfile(data);
        byte[] rawProfile = getProfileBase().retrieveRawProfile(null, newProfileId);
        return Response.status(Response.Status.CREATED)
                .entity(rawProfile)
                .type(MediaType.APPLICATION_OCTET_STREAM)
                .build();
    }

    @POST
    @Path("{profileId}")
    public Response modifyProfileState(
            @PathParam("profileId") String profileId,
            @QueryParam("action") String action) throws Exception {

        getProfileBase().modifyProfileState(CAEngineQuarkus.toPKIPrincipal(identity), profileId, action);
        return Response.noContent().build();
    }

    @PUT
    @Path("{profileId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyProfile(
            @PathParam("profileId") String profileId,
            String requestData) throws Exception {

        ProfileData reqProfile = JSONSerializer.fromJSON(requestData, ProfileData.class);
        ProfileData newProfile = getProfileBase().modifyProfile(null, profileId, reqProfile);
        return Response.ok(newProfile.toJSON()).build();
    }

    @PUT
    @Path("{profileId}/raw")
    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response modifyProfileRaw(
            @PathParam("profileId") String profileId,
            byte[] data) throws Exception {

        byte[] newRawProfile = getProfileBase().modifyProfile(profileId, data);
        return Response.ok(newRawProfile).type(MediaType.APPLICATION_OCTET_STREAM).build();
    }

    @DELETE
    @Path("{profileId}")
    public Response deleteProfile(@PathParam("profileId") String profileId) throws Exception {
        getProfileBase().deleteProfile(profileId);
        return Response.noContent().build();
    }
}

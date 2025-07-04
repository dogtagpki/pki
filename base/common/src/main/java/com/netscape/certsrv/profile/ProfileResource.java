package com.netscape.certsrv.profile;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;

@Path("profiles")
@AuthMethodMapping("profiles")
public interface ProfileResource {

    @GET
    @ACLMapping("profiles.list")
    public Response listProfiles(
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size,
            @QueryParam("visible") Boolean visible,
            @QueryParam("enable") Boolean enable,
            @QueryParam("enableBy") String enableBy);

    @GET
    @Path("{id}")
    @ACLMapping("profiles.read")
    public Response retrieveProfile(@PathParam("id") String id);

    @GET
    @Path("{id}/raw")
    @ACLMapping("profiles.read")
    public Response retrieveProfileRaw(@PathParam("id") String id) throws Exception;

    @POST
    @ACLMapping("profiles.create")
    public Response createProfile(String profileData) throws Exception;

    @POST
    @Path("raw")
    @ACLMapping("profiles.create")
    public Response createProfileRaw(byte[] data) throws Exception;

    @POST
    @Path("{id}")
    @ACLMapping("profiles.approve")
    public Response modifyProfileState(@PathParam("id") String id, @QueryParam("action") String action) throws Exception;

    @PUT
    @Path("{id}")
    @ACLMapping("profiles.modify")
    public Response modifyProfile(@PathParam("id") String id, String modifyProfileRequest) throws Exception;

    @PUT
    @Path("{id}/raw")
    @ACLMapping("profiles.modify")
    public Response modifyProfileRaw(@PathParam("id") String id, byte[] data) throws Exception;

    @DELETE
    @Path("{id}")
    @ACLMapping("profiles.delete")
    public Response deleteProfile(@PathParam("id") String id);
}

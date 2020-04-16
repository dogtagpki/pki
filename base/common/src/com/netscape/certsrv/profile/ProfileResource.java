package com.netscape.certsrv.profile;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;

@Path("profiles")
@AuthMethodMapping("profiles")
public interface ProfileResource {

    @GET
    @ACLMapping("profiles.list")
    public Response listProfiles(
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

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
    public Response createProfile(ProfileData data) throws Exception;

    @POST
    @Path("raw")
    @ACLMapping("profiles.create")
    public Response createProfileRaw(byte[] data);

    @POST
    @Path("{id}")
    @ACLMapping("profiles.approve")
    public Response modifyProfileState(@PathParam("id") String id, @QueryParam("action") String action) throws Exception;

    @PUT
    @Path("{id}")
    @ACLMapping("profiles.modify")
    public Response modifyProfile(@PathParam("id") String id, ProfileData data) throws Exception;

    @PUT
    @Path("{id}/raw")
    @ACLMapping("profiles.modify")
    public Response modifyProfileRaw(@PathParam("id") String id, byte[] data) throws Exception;

    @DELETE
    @Path("{id}")
    @ACLMapping("profiles.delete")
    public Response deleteProfile(@PathParam("id") String id);
}

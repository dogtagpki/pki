package com.netscape.certsrv.profile;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;

@Path("profiles")
@AuthMethodMapping("profiles")
public interface ProfileResource {

    @GET
    @ClientResponseType(entityType=ProfileDataInfos.class)
    @ACLMapping("profiles.list")
    public Response listProfiles(
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{id}")
    @ClientResponseType(entityType=ProfileData.class)
    @ACLMapping("profiles.read")
    public Response retrieveProfile(@PathParam("id") String id);

    @POST
    @ClientResponseType(entityType=ProfileData.class)
    @ACLMapping("profiles.create")
    public Response createProfile(ProfileData data);

    @POST
    @Path("{id}")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("profiles.approve")
    public Response modifyProfileState(@PathParam("id") String id, @QueryParam("action") String action);

    @PUT
    @Path("{id}")
    @ClientResponseType(entityType=ProfileData.class)
    @ACLMapping("profiles.modify")
    public Response modifyProfile(@PathParam("id") String id, ProfileData data);

    @DELETE
    @Path("{id}")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("profiles.delete")
    public Response deleteProfile(@PathParam("id") String id);
}
package com.netscape.certsrv.profile;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.netscape.certsrv.authentication.AuthMethodMapping;

@Path("")
public interface ProfileResource {

    @GET
    @Path("profiles")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public ProfileDataInfos listProfiles();

    @GET
    @Path("profiles/{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public ProfileData retrieveProfile(@PathParam("id") String id);

    @POST
    @Path("admin/profiles")
    @AuthMethodMapping("admin")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void createProfile(ProfileData data);

    @POST
    @Path("agent/profiles/{id}")
    @AuthMethodMapping("agent")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void modifyProfileState(@PathParam("id") String id, @QueryParam("action") String action);

    @PUT
    @Path("admin/profiles/{id}")
    @AuthMethodMapping("admin")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void modifyProfile(@PathParam("id") String id, ProfileData data);

    @DELETE
    @Path("admin/profiles/{id}")
    @AuthMethodMapping("admin")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void deleteProfile(@PathParam("id") String id);

}
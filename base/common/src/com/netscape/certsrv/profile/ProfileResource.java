package com.netscape.certsrv.profile;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.netscape.certsrv.authentication.AuthMethodMapping;


@Path("agent/profiles")
@AuthMethodMapping("agent")
public interface ProfileResource {

    @GET
    @Path("{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public ProfileData retrieveProfile(@PathParam("id") String id);

    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public ProfileDataInfos listProfiles();

    /**
     * Used to retrieve a key
     *
     * @param data
     * @return
     */

    /*
    @POST
    @Path("retrieve")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public ProfileData retrieveProfile(ProfileRetrievalRequestData request);

    // retrieval - used to test integration with a browser
    @POST
    @Path("retrieve")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED })
    public ProfileData retrievProfile(MultivaluedMap<String, String> form);
    */
}
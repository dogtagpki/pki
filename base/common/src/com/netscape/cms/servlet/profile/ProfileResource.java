package com.netscape.cms.servlet.profile;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.netscape.cms.servlet.profile.model.ProfileData;
import com.netscape.cms.servlet.profile.model.ProfileDataInfos;

@Path("/profiles")
public interface ProfileResource {

    @GET
    @Path("{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public ProfileData retrieveProfile(@PathParam("id") String id);

    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
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
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public ProfileData retrieveProfile(ProfileRetrievalRequestData request);

    // retrieval - used to test integration with a browser
    @POST
    @Path("retrieve")
    @Produces(MediaType.TEXT_XML)
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED })
    public ProfileData retrievProfile(MultivaluedMap<String, String> form);
    */
}
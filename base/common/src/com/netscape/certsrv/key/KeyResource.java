package com.netscape.certsrv.key;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;


@Path("agent/keys")
@ACLMapping("keys")
@AuthMethodMapping("keys")
public interface KeyResource {

    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyDataInfos listKeys(@QueryParam("clientID") String clientID,
                                 @QueryParam("status") String status,
                                 @QueryParam("maxResults") Integer maxResults,
                                 @QueryParam("maxTime") Integer maxTime,
                                 @QueryParam("start") Integer start,
                                 @QueryParam("size") Integer size);


    /**
     * Used to retrieve a key
     * @param data
     * @return
     */
    @POST
    @Path("retrieve")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyData retrieveKey(KeyRecoveryRequest data);

    // retrieval - used to test integration with a browser
    @POST
    @Path("retrieve")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED })
    public KeyData retrieveKey(MultivaluedMap<String, String> form);
}

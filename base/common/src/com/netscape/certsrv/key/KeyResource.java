package com.netscape.certsrv.key;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.dbs.keydb.KeyId;


@Path("agent/keys")
@ACLMapping("keys")
@AuthMethodMapping("keys")
public interface KeyResource {

    @GET
    @ClientResponseType(entityType=KeyInfoCollection.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response listKeys(@QueryParam("clientID") String clientID,
                                 @QueryParam("status") String status,
                                 @QueryParam("maxResults") Integer maxResults,
                                 @QueryParam("maxTime") Integer maxTime,
                                 @QueryParam("start") Integer start,
                                 @QueryParam("size") Integer size);

    @GET
    @Path("active/{clientID}")
    @ClientResponseType(entityType=KeyInfo.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response getActiveKeyInfo(@PathParam("clientID") String clientID);

    @GET
    @Path("{id}")
    @ClientResponseType(entityType=KeyInfo.class)
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public Response getKeyInfo(@PathParam("id") KeyId id);

    @POST
    @Path("{id}")
    @ClientResponseType(entityType=Void.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response modifyKeyStatus(@PathParam("id") KeyId id,
                                    @QueryParam("status") String status);

    /**
     * Used to retrieve a key
     * @param data
     * @return
     */
    @POST
    @Path("retrieve")
    @ClientResponseType(entityType=KeyData.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response retrieveKey(KeyRecoveryRequest data);

    // retrieval - used to test integration with a browser
    @POST
    @Path("retrieve")
    @ClientResponseType(entityType=KeyData.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED })
    public Response retrieveKey(MultivaluedMap<String, String> form);
}

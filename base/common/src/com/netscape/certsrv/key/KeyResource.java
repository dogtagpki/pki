package com.netscape.certsrv.key;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.dbs.keydb.KeyId;


@Path("agent/keys")
@ACLMapping("keys")
@AuthMethodMapping("keys")
public interface KeyResource {

    public static final String KEY_STATUS_ACTIVE = "active";
    public static final String KEY_STATUS_INACTIVE = "inactive";

    @GET
    public Response listKeys(@QueryParam("clientKeyID") String clientKeyID,
                                 @QueryParam("status") String status,
                                 @QueryParam("maxResults") Integer maxResults,
                                 @QueryParam("maxTime") Integer maxTime,
                                 @QueryParam("start") Integer start,
                                 @QueryParam("size") Integer size,
                                 @QueryParam("realm") String realm);

    @GET
    @Path("active/{clientKeyID}")
    public Response getActiveKeyInfo(@PathParam("clientKeyID") String clientKeyID);

    @GET
    @Path("{id}")
    public Response getKeyInfo(@PathParam("id") KeyId id);

    @POST
    @Path("{id}")
    public Response modifyKeyStatus(@PathParam("id") KeyId id,
                                    @QueryParam("status") String status);

    /**
     * Used to retrieve a key
     * @param data
     */
    @POST
    @Path("retrieve")
    public Response retrieveKey(KeyRecoveryRequest data);

    // retrieval - used to test integration with a browser
    @POST
    @Path("retrieve")
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED })
    public Response retrieveKey(MultivaluedMap<String, String> form);
}

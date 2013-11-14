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
import com.netscape.certsrv.request.RequestId;

@Path("agent/keyrequests")
@ACLMapping("keyrequests")
@AuthMethodMapping("keyrequests")
public interface KeyRequestResource {

    public final String SYMMETRIC_KEY_TYPE = "symmetricKey";
    public final String PASS_PHRASE_TYPE = "passPhrase";
    public final String ASYMMETRIC_KEY_TYPE = "asymmetricKey";

    /**
     * Used to generate list of key requests based on the search parameters
     */
    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyRequestInfos listRequests(@QueryParam("requestState") String requestState,
                                            @QueryParam("requestType") String requestType,
                                            @QueryParam("clientID") String clientID,
                                            @QueryParam("start") RequestId start,
                                            @QueryParam("pageSize") Integer pageSize,
                                            @QueryParam("maxResults") Integer maxResults,
                                            @QueryParam("maxTime") Integer maxTime);


    /**
     * Used to retrieve key request info for a specific request
     */
    @GET
    @Path("{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyRequestInfo getRequestInfo(@PathParam("id") RequestId id);

    // Archiving - used to test integration with a browser
    @POST
    @Path("archive")
    @ClientResponseType(entityType=KeyRequestInfo.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED})
    public Response archiveKey(MultivaluedMap<String, String> form);

    @POST
    @Path("archive")
    @ClientResponseType(entityType=KeyRequestInfo.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response archiveKey(KeyArchivalRequest data);

    //Recovery - used to test integration with a browser
    @POST
    @Path("recover")
    @ClientResponseType(entityType=KeyRequestInfo.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED})
    public Response recoverKey(MultivaluedMap<String, String> form);

    @POST
    @Path("recover")
    @ClientResponseType(entityType=KeyRequestInfo.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response recoverKey(KeyRecoveryRequest data);

    @POST
    @Path("{id}/approve")
    public void approveRequest(@PathParam("id") RequestId id);

    @POST
    @Path("{id}/reject")
    public void rejectRequest(@PathParam("id") RequestId id);

    @POST
    @Path("{id}/cancel")
    public void cancelRequest(@PathParam("id") RequestId id);

}

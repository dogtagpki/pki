package com.netscape.certsrv.key;

import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.request.RequestId;

@Path("agent/keyrequests")
public interface KeyRequestResource {

    public final String SYMMETRIC_KEY_TYPE = "symmetricKey";
    public final String PASS_PHRASE_TYPE = "passPhrase";
    public final String ASYMMETRIC_KEY_TYPE = "asymmetricKey";

    public static final int DEFAULT_START = 0;
    public static final int DEFAULT_PAGESIZE = 20;
    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;

    /**
     * Used to generate list of key requests based on the search parameters
     */
    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyRequestInfos listRequests(@QueryParam("requestState") String requestState,
                                            @QueryParam("requestType") String requestType,
                                            @QueryParam("clientID") String clientID,
                                            @DefaultValue(""+DEFAULT_START) @QueryParam("start") RequestId start,
                                            @DefaultValue(""+DEFAULT_PAGESIZE) @QueryParam("pageSize") int pageSize,
                                            @DefaultValue(""+DEFAULT_MAXRESULTS) @QueryParam("maxResults") int maxResults,
                                            @DefaultValue(""+DEFAULT_MAXTIME) @QueryParam("maxTime") int maxTime);


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
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED})
    public KeyRequestInfo archiveKey(MultivaluedMap<String, String> form);

    @POST
    @Path("archive")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyRequestInfo archiveKey(KeyArchivalRequest data);

    //Recovery - used to test integration with a browser
    @POST
    @Path("recover")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED})
    public KeyRequestInfo recoverKey(MultivaluedMap<String, String> form);

    @POST
    @Path("recover")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyRequestInfo recoverKey(KeyRecoveryRequest data);

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

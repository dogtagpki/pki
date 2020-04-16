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
import com.netscape.certsrv.base.ResourceMessage;
import com.netscape.certsrv.request.RequestId;

@Path("agent/keyrequests")
@ACLMapping("keyrequests")
@AuthMethodMapping("keyrequests")
public interface KeyRequestResource {

    /* Data types */
    public static final String SYMMETRIC_KEY_TYPE = "symmetricKey";
    public static final String PASS_PHRASE_TYPE = "passPhrase";
    public static final String ASYMMETRIC_KEY_TYPE = "asymmetricKey";

    /* Symmetric Key Algorithms */
    public static final String DES_ALGORITHM = "DES";
    public static final String DESEDE_ALGORITHM = "DESede";
    public static final String DES3_ALGORITHM = "DES3";
    public static final String RC2_ALGORITHM = "RC2";
    public static final String RC4_ALGORITHM = "RC4";
    public static final String AES_ALGORITHM = "AES";

    // Asymmetric Key algorithms
    public final static String RSA_ALGORITHM = "RSA";
    public final static String DSA_ALGORITHM = "DSA";
    public final static String EC_ALGORITHM = "EC"; // Not supported yet.

    /**
     * Used to generate list of key requests based on the search parameters
     */
    @GET
    public Response listRequests(@QueryParam("requestState") String requestState,
                                            @QueryParam("requestType") String requestType,
                                            @QueryParam("clientKeyID") String clientKeyID,
                                            @QueryParam("start") RequestId start,
                                            @QueryParam("pageSize") Integer pageSize,
                                            @QueryParam("maxResults") Integer maxResults,
                                            @QueryParam("maxTime") Integer maxTime,
                                            @QueryParam("realm") String realm);

    @POST
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED})
    public Response submitRequest(MultivaluedMap<String, String> form) throws Exception;

    @POST
    public Response submitRequest(ResourceMessage data) throws Exception;

    /**
     * Used to retrieve key request info for a specific request
     */
    @GET
    @Path("{id}")
    public Response getRequestInfo(@PathParam("id") RequestId id);

    @POST
    @Path("{id}/approve")
    public Response approveRequest(@PathParam("id") RequestId id);

    @POST
    @Path("{id}/reject")
    public Response rejectRequest(@PathParam("id") RequestId id);

    @POST
    @Path("{id}/cancel")
    public Response cancelRequest(@PathParam("id") RequestId id);
}

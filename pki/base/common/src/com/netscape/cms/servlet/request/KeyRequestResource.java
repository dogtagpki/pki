package com.netscape.cms.servlet.request;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.Consumes;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.request.model.ArchivalRequestData;
import com.netscape.cms.servlet.request.model.KeyRequestInfo;
import com.netscape.cms.servlet.request.model.RecoveryRequestData;

@Path("/keyrequest")
public interface KeyRequestResource {
    public final String SYMMETRIC_KEY_TYPE = "symmetricKey";
    public final String PASS_PHRASE_TYPE = "passPhrase";
    public final String ASYMMETRIC_KEY_TYPE = "asymmetricKey";

    /**
     * Used to retrieve key request info for a specific request
     */
    @GET
    @Path("{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public KeyRequestInfo getRequestInfo(@PathParam("id") RequestId id);

    // Archiving - used to test integration with a browser
    @POST
    @Path("archive")
    @Produces({ MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED})
    public KeyRequestInfo archiveKey(MultivaluedMap<String, String> form);

    @POST
    @Path("archive")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyRequestInfo archiveKey(ArchivalRequestData data);

    //Recovery - used to test integration with a browser
    @POST
    @Path("recover")
    @Produces({ MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED})
    public KeyRequestInfo recoverKey(MultivaluedMap<String, String> form);

    @POST
    @Path("recover")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyRequestInfo recoverKey(RecoveryRequestData data);

    @POST
    @Path("approve/{id}")
    public void approveRequest(@PathParam("id") RequestId id);

    @POST
    @Path("reject/{id}")
    public void rejectRequest(@PathParam("id") RequestId id);

    @POST
    @Path("cancel/{id}")
    public void cancelRequest(@PathParam("id") RequestId id);

}

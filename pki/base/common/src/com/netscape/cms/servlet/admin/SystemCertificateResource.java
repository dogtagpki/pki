package com.netscape.cms.servlet.admin;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/config/cert")
public interface SystemCertificateResource {

    /**
     * Used to retrieve the transport certificate
     */
    @GET
    @Path("/transport")
    //@ClientResponseType(CertificateData.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public Response getTransportCert();

}
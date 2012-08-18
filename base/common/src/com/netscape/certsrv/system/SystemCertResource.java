package com.netscape.certsrv.system;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.cert.CertData;

@Path("config/cert")
public interface SystemCertResource {

    /**
     * Used to retrieve the transport certificate
     */
    @GET
    @Path("transport")
    @ClientResponseType(entityType=CertData.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response getTransportCert();

}
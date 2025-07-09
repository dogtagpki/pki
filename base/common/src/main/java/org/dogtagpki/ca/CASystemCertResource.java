package org.dogtagpki.ca;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

@Path("config/cert")
public interface CASystemCertResource {

    @GET
    @Path("signing")
    public Response getSigningCert() throws Exception;

    @GET
    @Path("transport")
    public Response getTransportCert() throws Exception;
}

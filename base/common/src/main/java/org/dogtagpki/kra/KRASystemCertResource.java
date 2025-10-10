package org.dogtagpki.kra;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

@Path("config/cert")
public interface KRASystemCertResource {

    @GET
    @Path("transport")
    public Response getTransportCert() throws Exception;
}

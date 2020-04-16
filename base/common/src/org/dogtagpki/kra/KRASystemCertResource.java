package org.dogtagpki.kra;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("config/cert")
public interface KRASystemCertResource {

    @GET
    @Path("transport")
    public Response getTransportCert() throws Exception;
}

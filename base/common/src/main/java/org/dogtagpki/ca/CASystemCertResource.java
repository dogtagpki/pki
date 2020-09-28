package org.dogtagpki.ca;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("config/cert")
public interface CASystemCertResource {

    @GET
    @Path("signing")
    public Response getSigningCert() throws Exception;

    @GET
    @Path("transport")
    public Response getTransportCert() throws Exception;
}

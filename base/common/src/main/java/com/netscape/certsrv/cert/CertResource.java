package com.netscape.certsrv.cert;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import com.netscape.certsrv.dbs.certdb.CertId;

@Path("certs")
public interface CertResource {

    @GET
    @Path("")
    public Response listCerts(
            @QueryParam("status") String status,
            @QueryParam("maxResults") Integer maxResults,
            @QueryParam("maxTime") Integer maxTime,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @Path("search")
    public Response searchCerts(
            String searchRequest,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{id}")
    public Response getCert(@PathParam("id") CertId id);
}

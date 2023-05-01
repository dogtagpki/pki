package com.netscape.certsrv.cert;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

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

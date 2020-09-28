package com.netscape.certsrv.cert;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.dbs.certdb.CertId;

@Path("")
public interface CertResource {

    @GET
    @Path("certs")
    public Response listCerts(
            @QueryParam("status") String status,
            @QueryParam("maxResults") Integer maxResults,
            @QueryParam("maxTime") Integer maxTime,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @Path("certs/search")
    public Response searchCerts(
            CertSearchRequest data,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("certs/{id}")
    public Response getCert(@PathParam("id") CertId id);

    @GET
    @Path("agent/certs/{id}")
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response reviewCert(@PathParam("id") CertId id);

    @POST
    @Path("agent/certs/{id}/revoke-ca")
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response revokeCACert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("agent/certs/{id}/revoke")
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response revokeCert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("agent/certs/{id}/unrevoke")
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response unrevokeCert(@PathParam("id") CertId id);
}

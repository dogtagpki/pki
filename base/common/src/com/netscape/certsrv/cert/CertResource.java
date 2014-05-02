package com.netscape.certsrv.cert;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.dbs.certdb.CertId;

@Path("")
public interface CertResource {

    @GET
    @Path("certs")
    @ClientResponseType(entityType=CertDataInfos.class)
    public Response listCerts(
            @QueryParam("status") String status,
            @QueryParam("maxResults") Integer maxResults,
            @QueryParam("maxTime") Integer maxTime,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @Path("certs/search")
    @ClientResponseType(entityType=CertDataInfos.class)
    public Response searchCerts(
            CertSearchRequest data,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("certs/{id}")
    @ClientResponseType(entityType=CertData.class)
    public Response getCert(@PathParam("id") CertId id);

    @GET
    @Path("agent/certs/{id}")
    @ClientResponseType(entityType=CertData.class)
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response reviewCert(@PathParam("id") CertId id);

    @POST
    @Path("agent/certs/{id}/revoke-ca")
    @ClientResponseType(entityType=CertRequestInfo.class)
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response revokeCACert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("agent/certs/{id}/revoke")
    @ClientResponseType(entityType=CertRequestInfo.class)
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response revokeCert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("agent/certs/{id}/unrevoke")
    @ClientResponseType(entityType=CertRequestInfo.class)
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response unrevokeCert(@PathParam("id") CertId id);
}

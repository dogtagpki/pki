package com.netscape.certsrv.cert;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.dbs.certdb.CertId;

@Path("")
public interface CertResource {

    @GET
    @Path("certs")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public CertDataInfos listCerts(
            @QueryParam("status") String status,
            @QueryParam("maxResults") Integer maxResults,
            @QueryParam("maxTime") Integer maxTime,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @Path("certs/search")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public CertDataInfos searchCerts(
            CertSearchRequest data,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("certs/{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public CertData getCert(@PathParam("id") CertId id);

    @GET
    @Path("agent/certs/{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public CertData reviewCert(@PathParam("id") CertId id);

    @POST
    @Path("agent/certs/{id}/revoke-ca")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public CertRequestInfo revokeCACert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("agent/certs/{id}/revoke")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public CertRequestInfo revokeCert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("agent/certs/{id}/unrevoke")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public CertRequestInfo unrevokeCert(@PathParam("id") CertId id, CertUnrevokeRequest request);
}

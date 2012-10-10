package com.netscape.certsrv.cert;

import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.dbs.certdb.CertId;

@Path("")
public interface CertResource {

    public static final int DEFAULT_MAXTIME = 0;
    public static final int DEFAULT_MAXRESULTS = 20;

    @GET
    @Path("certs")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public CertDataInfos listCerts(
            @QueryParam("status") String status,
            @DefaultValue("" + DEFAULT_MAXRESULTS) @QueryParam("maxResults") int maxResults,
            @DefaultValue("" + DEFAULT_MAXTIME) @QueryParam("maxTime") int maxTime);

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

    @POST
    @Path("agent/certs/{id}/revoke-ca")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("agent.certs")
    public CertRequestInfo revokeCACert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("agent/certs/{id}/revoke")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("agent.certs")
    public CertRequestInfo revokeCert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("agent/certs/{id}/unrevoke")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("agent.certs")
    public CertRequestInfo unrevokeCert(@PathParam("id") CertId id, CertUnrevokeRequest request);
}

package com.netscape.certsrv.cert;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.dbs.certdb.CertId;

@Path("agent/certs")
public interface AgentCertResource {

    @GET
    @Path("{id}")
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response reviewCert(@PathParam("id") CertId id);

    @POST
    @Path("{id}/revoke-ca")
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response revokeCACert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("{id}/revoke")
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response revokeCert(@PathParam("id") CertId id, CertRevokeRequest request);

    @POST
    @Path("{id}/unrevoke")
    @ACLMapping("certs")
    @AuthMethodMapping("certs")
    public Response unrevokeCert(@PathParam("id") CertId id);
}

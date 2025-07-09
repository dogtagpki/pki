package com.netscape.certsrv.cert;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Response;

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

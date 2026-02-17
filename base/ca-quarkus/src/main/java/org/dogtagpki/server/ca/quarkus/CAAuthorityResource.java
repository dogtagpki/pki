//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.List;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.rest.base.AuthorityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.base.MimeType;
import com.netscape.certsrv.base.RequestNotAcceptable;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * JAX-RS resource for CA authority (sub-CA) operations.
 * Replaces AuthorityServlet.
 */
@Path("v2/authorities")
public class CAAuthorityResource {

    private static final Logger logger = LoggerFactory.getLogger(CAAuthorityResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findCAs(
            @QueryParam("id") String id,
            @QueryParam("parentID") String parentID,
            @QueryParam("dn") String dn,
            @QueryParam("issuerDN") String issuerDN) throws Exception {

        logger.info("CAAuthorityResource: Finding CAs");
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        List<AuthorityData> authorities = authorityRepository.findCAs(id, parentID, dn, issuerDN);

        ObjectMapper mapper = new ObjectMapper();
        return Response.ok(mapper.writeValueAsString(authorities)).build();
    }

    @GET
    @Path("{authorityId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCA(@PathParam("authorityId") String aid) throws Exception {
        logger.info("CAAuthorityResource: Getting CA {}", aid);
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData ca = authorityRepository.getCA(aid);
        return Response.ok(ca.toJSON()).build();
    }

    @GET
    @Path("{authorityId}/cert")
    @Produces({MimeType.APPLICATION_X_PEM_FILE, MimeType.APPLICATION_PKIX_CERT, MediaType.WILDCARD})
    public Response getCert(
            @PathParam("authorityId") String aid,
            @jakarta.ws.rs.HeaderParam("Accept") String accept) throws Exception {

        logger.info("CAAuthorityResource: Getting cert for CA {}", aid);
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();

        if (accept == null) accept = MimeType.ANYTYPE;

        if (accept.contains(MimeType.APPLICATION_X_PEM_FILE)) {
            String cert = authorityRepository.getPemCert(aid);
            return Response.ok(cert).type(MimeType.APPLICATION_X_PEM_FILE).build();
        }

        if (accept.equals(MimeType.ANYTYPE) || accept.contains(MimeType.APPLICATION_PKIX_CERT)) {
            byte[] cert = authorityRepository.getBinaryCert(aid);
            return Response.ok(cert).type(MimeType.APPLICATION_PKIX_CERT).build();
        }

        throw new RequestNotAcceptable("Certificate format not supported: " + accept);
    }

    @GET
    @Path("{authorityId}/chain")
    @Produces({MimeType.APPLICATION_X_PEM_FILE, MimeType.APPLICATION_PKCS7, MediaType.WILDCARD})
    public Response getChain(
            @PathParam("authorityId") String aid,
            @jakarta.ws.rs.HeaderParam("Accept") String accept) throws Exception {

        logger.info("CAAuthorityResource: Getting cert chain for CA {}", aid);
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();

        if (accept == null) accept = MimeType.ANYTYPE;

        if (accept.contains(MimeType.APPLICATION_X_PEM_FILE)) {
            String cert = authorityRepository.getPemChain(aid);
            return Response.ok(cert).type(MimeType.APPLICATION_X_PEM_FILE).build();
        }

        if (accept.equals(MimeType.ANYTYPE) || accept.contains(MimeType.APPLICATION_PKCS7)) {
            byte[] cert = authorityRepository.getBinaryChain(aid);
            return Response.ok(cert).type(MimeType.APPLICATION_PKCS7).build();
        }

        throw new RequestNotAcceptable("Certificate format not supported: " + accept);
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createCA(String requestData) throws Exception {
        logger.info("CAAuthorityResource: Creating CA");
        AuthorityData reqAuthority = JSONSerializer.fromJSON(requestData, AuthorityData.class);
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData newAuthority = authorityRepository.createCA(reqAuthority);
        return Response.status(Response.Status.CREATED)
                .entity(newAuthority.toJSON())
                .build();
    }

    @PUT
    @Path("{authorityId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyCA(
            @PathParam("authorityId") String aid,
            String requestData) throws Exception {

        logger.info("CAAuthorityResource: Modifying CA {}", aid);
        AuthorityData reqAuthority = JSONSerializer.fromJSON(requestData, AuthorityData.class);
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData newAuthority = authorityRepository.modifyCA(aid, reqAuthority);
        return Response.ok(newAuthority.toJSON()).build();
    }

    @DELETE
    @Path("{authorityId}")
    public Response deleteCA(@PathParam("authorityId") String aid) throws Exception {
        logger.info("CAAuthorityResource: Deleting CA {}", aid);
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        authorityRepository.deleteCA(aid, null);
        return Response.noContent().build();
    }

    @POST
    @Path("{authorityId}/enable")
    @Produces(MediaType.APPLICATION_JSON)
    public Response enableCA(@PathParam("authorityId") String aid) throws Exception {
        logger.info("CAAuthorityResource: Enabling CA {}", aid);
        AuthorityData reqAuthority = new AuthorityData(null, null, null, null, null, null, true, null, null);
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData newAuthority = authorityRepository.modifyCA(aid, reqAuthority);
        return Response.ok(newAuthority.toJSON()).build();
    }

    @POST
    @Path("{authorityId}/disable")
    @Produces(MediaType.APPLICATION_JSON)
    public Response disableCA(@PathParam("authorityId") String aid) throws Exception {
        logger.info("CAAuthorityResource: Disabling CA {}", aid);
        AuthorityData reqAuthority = new AuthorityData(null, null, null, null, null, null, false, null, null);
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData newAuthority = authorityRepository.modifyCA(aid, reqAuthority);
        return Response.ok(newAuthority.toJSON()).build();
    }

    @POST
    @Path("{authorityId}/renew")
    public Response renewCA(@PathParam("authorityId") String aid) throws Exception {
        logger.info("CAAuthorityResource: Renewing CA {}", aid);
        CAEngine engine = engineQuarkus.getEngine();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        authorityRepository.renewCA(aid, null);
        return Response.noContent().build();
    }
}

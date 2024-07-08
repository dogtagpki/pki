//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.issuer.ACMEIssuer;

/**
 * @author Endi S. Dewata
 */
@Path("cert/{id}")
@ACMEManagedService
public class ACMECertificateService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMECertificateService.class);

    @Context
    UriInfo uriInfo;

    @GET
    @Produces("application/pem-certificate-chain")
    public Response handleGET(@PathParam("id") String certID) throws Exception {
        return getCertificate(certID);
    }

    @POST
    @Produces("application/pem-certificate-chain")
    public Response handlePOST(@PathParam("id") String certID) throws Exception {
        return getCertificate(certID);
    }

    public Response getCertificate(String certID) throws Exception {

        logger.info("Retrieving certificate " + certID);

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEIssuer issuer = engine.getIssuer();
        String certChain = issuer.getCertificateChain(certID);

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getID());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        builder.entity(certChain);

        return builder.build();
    }
}

//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ACME certificate endpoint (RFC 8555 Section 7.4.2).
 *
 * @author Endi S. Dewata (original)
 */
@Path("cert")
@ACMEProtocolEndpoint
public class ACMECertificateResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMECertificateResource.class);

    private static final String APPLICATION_PEM_CERTIFICATE_CHAIN = "application/pem-certificate-chain";

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @GET
    @Path("{certID}")
    @Produces(APPLICATION_PEM_CERTIFICATE_CHAIN)
    public Response getCert(@PathParam("certID") String certID) throws Exception {
        return handleCertificate(certID);
    }

    @POST
    @Path("{certID}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(APPLICATION_PEM_CERTIFICATE_CHAIN)
    public Response postGetCert(@PathParam("certID") String certID, String requestData) throws Exception {
        return handleCertificate(certID);
    }

    private Response handleCertificate(String certID) throws Exception {

        logger.info("Retrieving certificate " + certID);

        ACMEIssuer issuer = engine.getIssuer();
        String certChain = issuer.getCertificateChain(certID);

        ACMENonce nonce = engine.createNonce();

        return Response.ok(certChain)
                .type(APPLICATION_PEM_CERTIFICATE_CHAIN)
                .header("Replay-Nonce", nonce.getID())
                .header("Link", getIndexLink())
                .build();
    }

    private String getIndexLink() {
        String baseUri = uriInfo.getBaseUri().toString();
        if (baseUri.endsWith("/")) {
            baseUri = baseUri.substring(0, baseUri.length() - 1);
        }
        return "<" + baseUri + "/directory>;rel=\"index\"";
    }
}

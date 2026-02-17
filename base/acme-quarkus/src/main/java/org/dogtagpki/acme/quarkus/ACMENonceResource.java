//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMENonce;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ACME new nonce endpoint (RFC 8555 Section 7.2).
 *
 * @author Endi S. Dewata (original)
 */
@Path("new-nonce")
@ACMEProtocolEndpoint
public class ACMENonceResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMENonceResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @HEAD
    public Response headNewNonce() throws Exception {
        logger.info("Creating nonce (HEAD)");

        ACMENonce nonce = engine.createNonce();

        return Response.ok()
                .header("Replay-Nonce", nonce.getID())
                .header("Cache-Control", "no-store")
                .header("Link", getIndexLink())
                .build();
    }

    @GET
    public Response getNewNonce() throws Exception {
        logger.info("Creating nonce (GET)");

        ACMENonce nonce = engine.createNonce();

        return Response.noContent()
                .header("Replay-Nonce", nonce.getID())
                .header("Cache-Control", "no-store")
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

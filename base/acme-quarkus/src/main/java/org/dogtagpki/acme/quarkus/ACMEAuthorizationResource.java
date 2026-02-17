//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.net.URI;
import java.util.Collection;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME authorization endpoint (RFC 8555 Section 7.5).
 *
 * @author Endi S. Dewata (original)
 */
@Path("authz")
@ACMEProtocolEndpoint
public class ACMEAuthorizationResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMEAuthorizationResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @POST
    @Path("{authzID}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthorization(@PathParam("authzID") String authzID, String requestData) throws Exception {

        logger.info("Checking authorization " + authzID);

        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);
        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        engine.validateNonce(header.getNonce());

        URI kid = header.getKid();
        String kidPath = kid.getPath();
        String accountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);
        logger.info("Account ID: " + accountID);

        ACMEAccount account = engine.getAccount(accountID);
        engine.validateJWS(jws, header.getAlg(), account.getJWK());

        ACMEAuthorization authorization = engine.getAuthorization(account, authzID);

        String baseUri = getBaseUri();
        Collection<ACMEChallenge> challenges = authorization.getChallenges();

        logger.info("Challenges:");
        for (ACMEChallenge challenge : challenges) {
            logger.info("- " + challenge.getType() + ": " + challenge.getStatus());
            challenge.setURL(new URI(baseUri + "/chall/" + challenge.getID()));
        }

        ACMENonce nonce = engine.createNonce();

        return Response.ok(authorization.toJSON())
                .header("Replay-Nonce", nonce.getID())
                .header("Link", getIndexLink())
                .build();
    }

    private String getBaseUri() {
        String baseUri = uriInfo.getBaseUri().toString();
        if (baseUri.endsWith("/")) {
            baseUri = baseUri.substring(0, baseUri.length() - 1);
        }
        return baseUri;
    }

    private String getIndexLink() {
        return "<" + getBaseUri() + "/directory>;rel=\"index\"";
    }
}

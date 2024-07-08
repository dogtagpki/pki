//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.util.Collection;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWS;

/**
 * @author Endi S. Dewata
 */
@Path("authz/{id}")
@ACMEManagedService
public class ACMEAuthorizationService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEAuthorizationService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST(@PathParam("id") String authzID, JWS jws) throws Exception {

        logger.info("Checking authorization " + authzID);

        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
        engine.validateNonce(header.getNonce());

        URI kid = header.getKid();
        String kidPath = kid.getPath();
        String accountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);
        logger.info("Account ID: " + accountID);

        ACMEAccount account = engine.getAccount(accountID);
        engine.validateJWS(jws, header.getAlg(), account.getJWK());

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        ACMEAuthorization authorization = engine.getAuthorization(account, authzID);
        String authorizationStatus = authorization.getStatus();
        logger.info("Authorization status: " + authorizationStatus);

        Collection<ACMEChallenge> challenges = authorization.getChallenges();

        logger.info("Challenges:");
        for (ACMEChallenge challenge : challenges) {
            logger.info("- " + challenge.getType() + ": " + challenge.getStatus());

            URI challengeURL = uriInfo.getBaseUriBuilder().path("chall").path(challenge.getID()).build();
            challenge.setURL(challengeURL);
        }

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getID());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        builder.entity(authorization);

        return builder.build();
    }
}

//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.codec.binary.Base64;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.validator.ACMEValidator;

/**
 * @author Endi S. Dewata
 */
@Path("authz/{id}")
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

        // generate 128-bit token with JSS
        // TODO: make it configurable

        byte[] bytes = new byte[16];
        SecureRandom random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
        random.nextBytes(bytes);
        String token = Base64.encodeBase64URLSafeString(bytes);
        logger.info("Token: " + token);

        Collection<ACMEChallenge> challenges = authorization.getChallenges();

        if (challenges == null || challenges.size() <= 0) {
            logger.info("Creating new challenges");
            challenges = new ArrayList<>();

            for (ACMEValidator validator : engine.getValidators()) {
                ACMEChallenge challenge = validator.createChallenge(authzID, token);
                challenges.add(challenge);
            }

            authorization.setChallenges(challenges);
            engine.updateAuthorization(account, authorization);
        }

        logger.info("Challenges:");
        for (ACMEChallenge challenge : challenges) {
            logger.info("- " + challenge.getType() + ": " + challenge.getStatus());

            URI challengeURL = uriInfo.getBaseUriBuilder().path("chall").path(challenge.getID()).build();
            challenge.setURL(challengeURL);
        }

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getValue());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        builder.entity(authorization);

        return builder.build();
    }
}

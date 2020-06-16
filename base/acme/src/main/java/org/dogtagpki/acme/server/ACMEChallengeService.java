//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

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
@Path("chall/{id}")
public class ACMEChallengeService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEChallengeService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST(@PathParam("id") String challengeID, JWS jws) throws Exception {

        logger.info("Validating challenge " + challengeID);

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

        ACMEAuthorization authorization = engine.getAuthorizationByChallenge(account, challengeID);

        String authzID = authorization.getID();

        ACMEChallenge challenge = authorization.getChallenge(challengeID);
        if (challenge == null) {
            // TODO: generate proper exception
            throw new Exception("Unknown challenge: " + challengeID);
        }

        String challengeStatus = challenge.getStatus();
        if (challengeStatus.equals("pending")) {

            String type = challenge.getType();
            logger.info("Challenge Type: " + type);

            ACMEValidator validator = engine.getValidator(type);
            if (validator == null) {
                // TODO: generate proper exception
                throw new Exception("Unsupported challenge type: " + type);
            }

            challenge.setStatus("processing");
            engine.updateAuthorization(account, authorization);

            ACMEChallengeProcessor processor = new ACMEChallengeProcessor(
                    account,
                    authorization,
                    challenge,
                    validator);

            // TODO: use thread pool
            new Thread(processor).start();

        } else if (challengeStatus.equals("processing")) {
            // TODO: retry the challenge

            // RFC 8555 Section 8.2: Retrying Challenges
            //
            // Clients can explicitly request a retry by re-sending their response
            // to a challenge in a new POST request (with a new nonce, etc.).  This
            // allows clients to request a retry when the state has changed (e.g.,
            // after firewall rules have been updated).  Servers SHOULD retry a
            // request immediately on receiving such a POST request.  In order to
            // avoid denial-of-service attacks via client-initiated retries, servers
            // SHOULD rate-limit such requests.

        } else {
            // TODO: generate proper exception
            throw new Exception("Challenge is already " + challengeStatus);
        }

        URI challengeURL = uriInfo.getBaseUriBuilder().path("chall").path(challengeID).build();
        challenge.setURL(challengeURL);

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getValue());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        URI authzURL = uriInfo.getBaseUriBuilder().path("authz").path(authzID).build();
        builder.link(authzURL, "up");

        builder.entity(challenge);

        return builder.build();
    }
}

//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.util.Date;

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
import org.dogtagpki.acme.ACMEOrder;
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

        URI challengeURL = uriInfo.getBaseUriBuilder().path("chall").path(challengeID).build();
        logger.info("Challenge URL: " + challengeURL);

        ACMEAuthorization authorization = engine.getAuthorizationByChallenge(account, challengeURL);

        String authzID = authorization.getID();
        URI authzURL = uriInfo.getBaseUriBuilder().path("authz").path(authzID).build();
        ACMEOrder order = engine.getOrderByAuthorization(account, authzURL);

        ACMEChallenge challenge = authorization.getChallenge(challengeURL);
        if (challenge == null) {
            // TODO: generate proper exception
            throw new Exception("Unknown challenge: " + challengeURL);
        }

        String type = challenge.getType();
        logger.info("Challenge Type: " + type);

        ACMEValidator validator = engine.getValidator(type);
        if (validator == null) {
            // TODO: generate proper exception
            throw new Exception("Unsupported challenge type: " + type);
        }

        String challengeStatus = challenge.getStatus();
        if (challengeStatus.equals("pending")) {
            challenge.setStatus("processing");
            engine.updateAuthorization(account, authorization);

        } else if (challengeStatus.equals("processing")) {
            // retrying the challenge, ignore

        } else {
            // TODO: generate proper exception
            throw new Exception("Challenge is already " + challengeStatus);
        }

        try {
            validator.validateChallenge(authorization, challenge);

        } catch (Exception e) {
            logger.info("Challenge " + challengeID + " is invalid");
            challenge.setStatus("invalid");
            engine.updateAuthorization(account, authorization);
            throw e;
        }

        logger.info("Challenge " + challengeID + " is valid");
        challenge.setStatus("valid");
        challenge.setValidationTime(new Date());

        logger.info("Authorization " + authzID + " is valid");
        authorization.setStatus("valid");

        engine.updateAuthorization(account, authorization);

        logger.info("Checking all authorizations in the order");
        boolean allAuthorizationsValid = true;

        for (URI url : order.getAuthorizations()) {
            String authzPath = url.getPath();
            String id = authzPath.substring(authzPath.lastIndexOf('/') + 1);
            ACMEAuthorization authz = engine.getAuthorization(account, id);

            if (authz.getStatus().equals("valid")) {
                continue;
            }

            allAuthorizationsValid = false;
            break;
        }

        if (allAuthorizationsValid) {
            logger.info("Order " + order.getID() + " is ready");
            order.setStatus("ready");
            engine.updateOrder(account, order);

        } else {
            logger.info("Order " + order.getID() + " is not ready");
        }

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getValue());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        builder.link(authzURL, "up");

        builder.entity(challenge);

        return builder.build();
    }
}

//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.util.Collection;
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

        ACMEAuthorization authorization = engine.getAuthorizationByChallenge(account, challengeID);

        String authzID = authorization.getID();

        ACMEChallenge challenge = authorization.getChallenge(challengeID);
        if (challenge == null) {
            // TODO: generate proper exception
            throw new Exception("Unknown challenge: " + challengeID);
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

        logger.info("Checking associated pending orders for validity");
        Collection<ACMEOrder> orders =
            engine.getOrdersByAuthorizationAndStatus(account, authzID, "pending");

        for (ACMEOrder order : orders) {
            boolean allAuthorizationsValid = true;

            for (String orderAuthzID : order.getAuthzIDs()) {
                ACMEAuthorization authz = engine.getAuthorization(account, orderAuthzID);
                if (authz.getStatus().equals("valid")) {
                    continue;
                } else {
                    allAuthorizationsValid = false;
                    break;
                }
            }

            if (allAuthorizationsValid) {
                logger.info("Order " + order.getID() + " is ready");
                order.setStatus("ready");
                engine.updateOrder(account, order);
            } else {
                logger.info("Order " + order.getID() + " is not ready");
            }
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

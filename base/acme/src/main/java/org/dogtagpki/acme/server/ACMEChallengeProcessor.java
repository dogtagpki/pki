//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.ValidationResult;
import org.dogtagpki.acme.validator.ACMEValidator;

/**
 * @author Endi S. Dewata
 */
public class ACMEChallengeProcessor implements Runnable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEChallengeProcessor.class);

    ACMEAccount account;
    ACMEAuthorization authorization;
    ACMEChallenge challenge;
    ACMEValidator validator;

    public ACMEChallengeProcessor(
            ACMEAccount account,
            ACMEAuthorization authorization,
            ACMEChallenge challenge,
            ACMEValidator validator) {

        this.account = account;
        this.authorization = authorization;
        this.challenge = challenge;
        this.validator = validator;
    }

    @Override
    public void run() {
        try {
            processChallenge();
        } catch (Exception e) {
            logger.error("Unable to process challenge " + challenge.getID() + ": " + e.getMessage(), e);
        }
    }

    public void processChallenge() throws Exception {

        String challengeID = challenge.getID();
        logger.info("Processing challenge " + challengeID);

        // TODO make retry parameters configurable
        int maxAttempts = 5;
        int delaySeconds = 5;
        int attempts = 0;
        ValidationResult r = null;

        while (attempts++ < maxAttempts) {
            try {
                r = validator.validateChallenge(authorization, challenge);
            } catch (Exception e) {
                ACMEError error = new ACMEError();
                error.setType("urn:ietf:params:acme:error:serverInternal");
                error.setDetail("Internal server error: " + e);
                r = ValidationResult.fail(error);
            }
            if (r.isOK()) break;
            Thread.sleep(delaySeconds * 1000);
        }

        if (r.isOK()) {
            finalizeValidAuthorization();
        } else {
            finalizeInvalidAuthorization(r.getError());
        }
    }

    public void finalizeValidAuthorization() throws Exception {

        Date currentTime = new Date();

        ACMEEngine engine = ACMEEngine.getInstance();
        String authzID = authorization.getID();
        String challengeID = challenge.getID();

        logger.info("Challenge " + challengeID + " is valid");
        challenge.setStatus("valid");
        challenge.setValidationTime(currentTime);

        // RFC 8555 Section 7.5.1: Responding to Challenges
        //
        // When finalizing an authorization, the server MAY remove challenges other
        // than the one that was completed, and it may modify the "expires" field.

        Collection<ACMEChallenge> challenges = new ArrayList<>();
        challenges.add(challenge);
        authorization.setChallenges(challenges);

        // RFC 8555 Section 7.1.6: Status Changes
        //
        // If one of the challenges listed in the authorization transitions to the
        // "valid" state, then the authorization also changes to the "valid" state.

        logger.info("Authorization " + authzID + " is valid");
        authorization.setStatus("valid");

        // RFC 8555 Section 7.5.1: Responding to Challenges
        //
        // If the final state is "valid", then the server MUST include an "expires"
        // field.

        Date expirationTime = engine.getPolicy().getValidAuthorizationExpirationTime(currentTime);
        authorization.setExpirationTime(expirationTime);

        logger.info("Updating pending orders");

        Collection<ACMEOrder> orders =
            engine.getOrdersByAuthorizationAndStatus(account, authzID, "pending");

        for (ACMEOrder order : orders) {
            boolean allAuthorizationsValid = true;

            for (String orderAuthzID : order.getAuthzIDs()) {
                if (orderAuthzID.equals(authzID)) {
                    // We're about to set it to valid, so treat it as such
                    continue;
                }

                ACMEAuthorization authz = engine.getAuthorization(account, orderAuthzID);
                if (authz.getStatus().equals("valid")) continue;

                allAuthorizationsValid = false;
                break;
            }

            if (!allAuthorizationsValid) continue;

            logger.info("Order " + order.getID() + " is ready");
            order.setStatus("ready");

            Date orderExpirationTime = engine.getPolicy().getReadyOrderExpirationTime(currentTime);
            order.setExpirationTime(orderExpirationTime);

            engine.updateOrder(account, order);
        }

        // We defer the LDAP update until AFTER any order transitions
        // occur.  This avoids a race condition where clients that eagerly
        // proceed to finalization when all Authorizations are "valid"
        // experience finalization failure, because the __Order__ has not yet
        // transition to "ready".
        engine.updateAuthorization(account, authorization);
    }

    public void finalizeInvalidAuthorization(ACMEError err) throws Exception {

        Date currentTime = new Date();

        ACMEEngine engine = ACMEEngine.getInstance();
        String authzID = authorization.getID();
        String challengeID = challenge.getID();

        // RFC 8555 Section 8.2: Retrying Challenges
        //
        // The server MUST provide information about its retry state to the
        // client via the "error" field in the challenge and the Retry-After
        // HTTP header field in response to requests to the challenge resource.
        // The server MUST add an entry to the "error" field in the challenge
        // after each failed validation query.  The server SHOULD set the Retry-
        // After header field to a time after the server's next validation
        // query, since the status of the challenge will not change until that
        // time.

        logger.info("Challenge " + challengeID + " is invalid");
        challenge.setStatus("invalid");
        challenge.setError(err.toJSON());

        // RFC 8555 Section 7.5.1: Responding to Challenges
        //
        // When finalizing an authorization, the server MAY remove challenges other
        // than the one that was completed, and it may modify the "expires" field.

        Collection<ACMEChallenge> challenges = new ArrayList<>();
        challenges.add(challenge);
        authorization.setChallenges(challenges);

        // RFC 8555 Section 7.1.6: Status Changes
        //
        // If the client attempts to fulfill a challenge and fails, or if there
        // is an error while the authorization is still pending, then the
        // authorization transitions to the "invalid" state.

        logger.info("Authorization " + authzID + " is invalid");
        authorization.setStatus("invalid");

        Date expirationTime = engine.getPolicy().getInvalidAuthorizationExpirationTime(currentTime);
        authorization.setExpirationTime(expirationTime);

        engine.updateAuthorization(account, authorization);

        // RFC 8555 Section 7.1.6: Status Changes
        //
        // The order also moves to the "invalid" state if it expires or one of
        // its authorizations enters a final state other than "valid" ("expired",
        // "revoked", or "deactivated").

        logger.info("Updating pending orders");

        Collection<ACMEOrder> orders =
            engine.getOrdersByAuthorizationAndStatus(account, authzID, "pending");

        for (ACMEOrder order : orders) {
            boolean allAuthorizationsValid = true;

            for (String orderAuthzID : order.getAuthzIDs()) {

                ACMEAuthorization authz = engine.getAuthorization(account, orderAuthzID);
                if (authz.getStatus().equals("valid")) continue;

                allAuthorizationsValid = false;
                break;
            }

            if (allAuthorizationsValid) continue;

            logger.info("Order " + order.getID() + " is invalid");
            order.setStatus("invalid");

            Date orderExpirationTime = engine.getPolicy().getInvalidOrderExpirationTime(currentTime);
            order.setExpirationTime(orderExpirationTime);

            engine.updateOrder(account, order);
        }
    }
}

//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

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
 * Quarkus version of ACMEChallengeProcessor.
 *
 * Uses ACMEEngineQuarkus.getInstance() instead of ACMEEngine.getInstance().
 *
 * @author Endi S. Dewata (original)
 */
public class ACMEChallengeProcessorQuarkus implements Runnable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEChallengeProcessorQuarkus.class);

    ACMEAccount account;
    ACMEAuthorization authorization;
    ACMEChallenge challenge;
    ACMEValidator validator;

    public ACMEChallengeProcessorQuarkus(
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

        ACMEEngineQuarkus engine = ACMEEngineQuarkus.getInstance();
        String authzID = authorization.getID();
        String challengeID = challenge.getID();

        logger.info("Challenge " + challengeID + " is valid");
        challenge.setStatus("valid");
        challenge.setValidationTime(currentTime);

        Collection<ACMEChallenge> challenges = new ArrayList<>();
        challenges.add(challenge);
        authorization.setChallenges(challenges);

        logger.info("Authorization " + authzID + " is valid");
        authorization.setStatus("valid");

        Date expirationTime = engine.getPolicy().getValidAuthorizationExpirationTime(currentTime);
        authorization.setExpirationTime(expirationTime);

        logger.info("Updating pending orders");

        Collection<ACMEOrder> orders =
            engine.getOrdersByAuthorizationAndStatus(account, authzID, "pending");

        for (ACMEOrder order : orders) {
            boolean allAuthorizationsValid = true;

            for (String orderAuthzID : order.getAuthzIDs()) {
                if (orderAuthzID.equals(authzID)) {
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

        engine.updateAuthorization(account, authorization);
    }

    public void finalizeInvalidAuthorization(ACMEError err) throws Exception {

        Date currentTime = new Date();

        ACMEEngineQuarkus engine = ACMEEngineQuarkus.getInstance();
        String authzID = authorization.getID();
        String challengeID = challenge.getID();

        logger.info("Challenge " + challengeID + " is invalid");
        challenge.setStatus("invalid");
        challenge.setError(err.toJSON());

        Collection<ACMEChallenge> challenges = new ArrayList<>();
        challenges.add(challenge);
        authorization.setChallenges(challenges);

        logger.info("Authorization " + authzID + " is invalid");
        authorization.setStatus("invalid");

        Date expirationTime = engine.getPolicy().getInvalidAuthorizationExpirationTime(currentTime);
        authorization.setExpirationTime(expirationTime);

        engine.updateAuthorization(account, authorization);

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

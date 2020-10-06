//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.validator;

import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.server.ACMEEngine;

/**
 * @author Endi S. Dewata
 */
public abstract class ACMEValidator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEValidator.class);

    protected String name;
    protected String type;

    protected ACMEValidatorConfig config;

    public ACMEValidator(String name, String type) {
        this.name = name;
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public ACMEValidatorConfig getConfig() {
        return config;
    }

    public void setConfig(ACMEValidatorConfig config) {
        this.config = config;
    }

    public void init() throws Exception {
    }

    public void close() throws Exception {
    }

    public ACMEChallenge createChallenge(
            String authzID,
            String token) throws Exception {

        ACMEEngine engine = ACMEEngine.getInstance();
        String challengeID = engine.randomAlphanumeric(10);
        logger.info("Creating " + name + " challenge: " + challengeID);

        ACMEChallenge challenge = new ACMEChallenge();
        challenge.setID(challengeID);
        challenge.setAuthzID(authzID);
        challenge.setType(type);
        challenge.setToken(token);
        challenge.setStatus("pending");

        return challenge;
    }

    /**
     * Validate the challenge.
     *
     * Validators SHOULD catch all exceptions (including unchecked
     * exceptions) and return an appropriate ValidationResult.
     */
    public abstract ValidationResult validateChallenge(
            ACMEAuthorization authorization,
            ACMEChallenge challenge);

}

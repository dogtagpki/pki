//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.validator;

import java.net.URI;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.RandomStringUtils;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEError;

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
            UriInfo uriInfo,
            String authzID,
            String token) throws Exception {

        // TODO: find better way to generate challenge ID

        String challengeID = RandomStringUtils.randomAlphanumeric(10);
        logger.info("Creating " + name + " challenge: " + challengeID);

        URI challengeURI = uriInfo.getBaseUriBuilder().path("chall").path(challengeID).build();

        ACMEChallenge challenge = new ACMEChallenge();
        challenge.setID(challengeID);
        challenge.setAuthzID(authzID);
        challenge.setType(type);
        challenge.setURL(challengeURI);
        challenge.setToken(token);
        challenge.setStatus("pending");

        return challenge;
    }

    public void validateChallenge(
            ACMEAuthorization authorization,
            ACMEChallenge challenge) throws Exception {
    }

    public void throwError(Response.Status status, ACMEError error) throws WebApplicationException {

        ResponseBuilder builder = Response.status(status);
        builder.type("application/problem+json");
        builder.entity(error);

        throw new WebApplicationException(builder.build());
    }
}

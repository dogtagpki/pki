//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.validator;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ValidationResult;

/**
 * @author Endi S. Dewata
 */
public class HTTP01Validator extends ACMEValidator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(HTTP01Validator.class);

    public HTTP01Validator() {
        super("HTTP-01", "http-01");
    }

    public ValidationResult validateChallenge(
            ACMEAuthorization authorization,
            ACMEChallenge challenge) {

        // HTTP-01 key authorization
        // https://tools.ietf.org/html/rfc8555

        String accountID = authorization.getAccountID();
        String token = challenge.getToken();
        String keyAuthorization = token + "." + accountID;
        logger.info("Key authorization: " + keyAuthorization);

        ACMEIdentifier identifier = authorization.getIdentifier();
        String hostname = identifier.getValue();
        String validationPath = "/.well-known/acme-challenge/" + token;

        URI validationURL;
        try {
            /* It was suggested to catch URISyntaxException and return
             * urn:ietf:params:acme:error:malformed.  A close inspection leads
             * to a different conclusion.
             *
             * `hostname` comes from `identifier` object, via `authorization`.
             * `validationPath` is derived from `token` which comes from
             * `challenge`.  All of the source objects are looked up
             * server-side, not supplied by the client.  If we got this far,
             * the client request was fine but there are missing or corrupt
             * data on the server side.  Therefore the correct error is
             * urn:ietf:params:acme:error:serverInternal.
             */
            validationURL = new URI("http", hostname, validationPath, null);
        } catch (URISyntaxException e) {
            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:serverInternal");
            error.setDetail(
                "Failed to construct validation URI for hostname '" + hostname + "' "
                + "and path '" + validationPath + "': " + e);
            return ValidationResult.fail(error);
        }

        String response = null;

        try {
            response = getResponse(validationURL);
        } catch (Exception e) {
            // TODO: catch more specific HTTP exception
            logger.info("Unable to validate HTTP-01 challenge: " + e.getMessage(), e);

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:connection");
            error.setDetail(
                    "Unable to validate HTTP-01 challenge at " + validationURL + "\n" +
                    "Error: " + e.getMessage());

            return ValidationResult.fail(error);
        }

        if (response == null || !response.equals(keyAuthorization)) {

            logger.error("Invalid response: " + response);

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:incorrectResponse");
            error.setDetail(
                    "Unable to validate HTTP-01 challenge at " + validationURL + "\n" +
                    "Incorrect response: " + response);

            return ValidationResult.fail(error);
        }

        return ValidationResult.ok();
    }

    public String getResponse(URI validationURL) throws Exception {

        logger.info("Retrieving " + validationURL);

        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(validationURL);
        CloseableHttpResponse httpResponse = httpClient.execute(httpGet);

        String response;
        try {
            HttpEntity entity = httpResponse.getEntity();
            response = IOUtils.toString(entity.getContent(), "UTF-8").trim();
            EntityUtils.consume(entity);

        } finally {
            httpResponse.close();
        }

        logger.info("Response: " + response);

        return response;
    }
}

//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.validator;

import java.net.URI;

import javax.ws.rs.core.Response;

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

/**
 * @author Endi S. Dewata
 */
public class HTTP01Validator extends ACMEValidator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(HTTP01Validator.class);

    public HTTP01Validator() {
        super("HTTP-01", "http-01");
    }

    public void validateChallenge(
            ACMEAuthorization authorization,
            ACMEChallenge challenge) throws Exception {

        // HTTP-01 key authorization
        // https://tools.ietf.org/html/rfc8555

        String accountID = authorization.getAccountID();
        String token = challenge.getToken();
        String keyAuthorization = token + "." + accountID;
        logger.info("Key authorization: " + keyAuthorization);

        ACMEIdentifier identifier = authorization.getIdentifier();
        String hostname = identifier.getValue();
        String validationPath = "/.well-known/acme-challenge/" + token;
        URI validationURL = new URI("http", hostname, validationPath, null);

        // TODO: move retry to ACMEChallengeProcessor.processChallenge()
        // TODO: make it configurable

        int maxCount = 5;
        int interval = 5;

        int count = 1;
        String response = null;
        Exception exception = null;

        while (true) {
            try {
                response = getResponse(validationURL);
                break;

            } catch (Exception e) {

                // TODO: catch more specific HTTP exception

                logger.error(e.getMessage());
                if (count >= maxCount) {
                    exception = e;
                    break;
                }

                Thread.sleep(interval * 1000);
                count++;
            }
        }

        if (exception != null) {

            logger.error("Unable to validate HTTP-01 challenge: " + exception.getMessage(), exception);

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:connection");
            error.setDetail(
                    "Unable to validate HTTP-01 challenge at " + validationURL + "\n" +
                    "Error: " + exception.getMessage());

            throwError(Response.Status.BAD_REQUEST, error);
        }

        if (response == null || !response.equals(keyAuthorization)) {

            logger.error("Invalid response: " + response);

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:incorrectResponse");
            error.setDetail(
                    "Unable to validate HTTP-01 challenge at " + validationURL + "\n" +
                    "Incorrect response: " + response);

            throwError(Response.Status.BAD_REQUEST, error);
        }
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

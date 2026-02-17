//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.util.Date;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME new account endpoint (RFC 8555 Section 7.3).
 *
 * @author Endi S. Dewata (original)
 */
@Path("new-account")
@ACMEProtocolEndpoint
public class ACMENewAccountResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMENewAccountResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createAccount(String requestData) throws Exception {

        logger.info("Creating new account");
        Date currentTime = new Date();

        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);
        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        engine.validateNonce(header.getNonce());

        JWK jwk = header.getJwk();
        logger.info("JWK: " + jwk);

        engine.validateJWS(jws, header.getAlg(), jwk);

        String accountID = engine.generateThumbprint(jwk);
        logger.info("Account ID: " + accountID);

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        String baseUri = getBaseUri();
        String accountUrl = baseUri + "/acct/" + accountID;

        ACMEAccount account = engine.getAccount(accountID, false);
        int status;

        if (account == null) {
            account = ACMEAccount.fromJSON(payload);

            Boolean onlyReturnExisting = account.getOnlyReturnExisting();
            if (onlyReturnExisting != null && onlyReturnExisting) {
                throw engine.createAccountDoesNotExistException(accountID);
            }

            logger.info("Creating new account");

            Boolean termsOfServiceAgreed = account.getTermsOfServiceAgreed();
            if (termsOfServiceAgreed == null || !termsOfServiceAgreed) {
                throw new Exception("Missing terms of service agreement");
            }

            account.setID(accountID);
            account.setCreationTime(currentTime);
            account.setJWK(jwk);
            account.setStatus("valid");

            engine.createAccount(account);
            status = 201;
        } else {
            logger.info("Account already exists");
            engine.validateAccount(accountID, account);
            status = 200;
        }

        account.setOrders(new java.net.URI(accountUrl + "/orders"));

        ACMENonce nonce = engine.createNonce();

        return Response.status(status)
                .header("Location", accountUrl)
                .header("Replay-Nonce", nonce.getID())
                .header("Link", getIndexLink())
                .entity(account.toJSON())
                .build();
    }

    private String getBaseUri() {
        String baseUri = uriInfo.getBaseUri().toString();
        if (baseUri.endsWith("/")) {
            baseUri = baseUri.substring(0, baseUri.length() - 1);
        }
        return baseUri;
    }

    private String getIndexLink() {
        return "<" + getBaseUri() + "/directory>;rel=\"index\"";
    }
}

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
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;

/**
 * @author Endi S. Dewata
 */
@Path("new-account")
public class ACMENewAccountService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMENewAccountService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response createNewAccount(JWS jws) throws Exception {

        logger.info("Creating new account");
        Date currentTime = new Date();

        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
        engine.validateNonce(header.getNonce());

        JWK jwk = header.getJwk();
        logger.info("JWK: " + jwk);

        engine.validateJWS(jws, header.getAlg(), jwk);

        // generate account ID from JWK thumbprint
        String accountID = engine.generateThumbprint(jwk);
        logger.info("Account ID: " + accountID);

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        URI accountURL = uriInfo.getBaseUriBuilder().path("acct").path(accountID).build();
        ResponseBuilder builder;

        ACMEAccount account = engine.getAccount(accountID, false);

        if (account == null) {

            account = ACMEAccount.fromJSON(payload);

            Boolean onlyReturnExisting = account.getOnlyReturnExisting();
            if (onlyReturnExisting != null && onlyReturnExisting) {
                throw engine.createAccountDoesNotExistException(accountID);
            }

            logger.info("Creating new account");

            Boolean termsOfServiceAgreed = account.getTermsOfServiceAgreed();
            if (termsOfServiceAgreed == null || !termsOfServiceAgreed) {
                // TODO: generate proper exception
                throw new Exception("Missing terms of service agreement");
            }

            account.setID(accountID);
            account.setCreationTime(currentTime);
            account.setJWK(jwk);
            account.setStatus("valid");

            engine.createAccount(account);

            builder = Response.created(accountURL);

        } else {

            logger.info("Account already exists");

            engine.validateAccount(accountID, account);

            builder = Response.ok();
            builder.location(accountURL);
        }

        // RFC 8555 Section 7.1.2.1 Orders List
        //
        // Each account object includes an "orders" URL from which a list of
        // orders created by the account can be fetched via POST-as-GET request.

        URI ordersURL = uriInfo.getBaseUriBuilder().path("acct").path(accountID).path("orders").build();
        account.setOrders(ordersURL);

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getID());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        builder.entity(account);

        return builder.build();
    }
}

//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import com.fasterxml.jackson.core.JsonProcessingException;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWS;

/**
 * @author Endi S. Dewata
 */
@Path("acct/{id}")
@ACMEManagedService
public class ACMEAccountService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEAccountService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateAccount(@PathParam("id") String accountID, JWS jws) throws Exception {

        logger.info("Updating account " + accountID);

        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
        engine.validateNonce(header.getNonce());

        URI kid = header.getKid();
        String kidPath = kid.getPath();
        String jwsAccountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);

        if (!accountID.equals(jwsAccountID)) {
            // TODO: generate proper exception
            throw new Exception("Invalid KID: " + kid);
        }

        ACMEAccount account = engine.getAccount(accountID);

        String status = account.getStatus();
        logger.info("Status: " + status);

        String[] contact = account.getContact();
        logger.info("Contact:");
        if (contact != null) {
            for (String c : contact) {
                logger.info("- " + c);
            }
        }

        engine.validateJWS(jws, header.getAlg(), account.getJWK());

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");

        if (payload.isEmpty()) {
            logger.info("Empty payload; treating as POST-as-GET");
        }

        else {
            logger.info("Payload: " + payload);

            ACMEAccount update;
            try {
                update = ACMEAccount.fromJSON(payload);
            } catch (JsonProcessingException e) {
                throw engine.createMalformedException(e.toString());
            }

            String newStatus = update.getStatus();
            if (newStatus != null) {
                logger.info("New status: " + newStatus);
                account.setStatus(newStatus);
            }

            String[] newContact = update.getContact();
            if (newContact != null) {
                logger.info("New contact:");
                for (String c : newContact) {
                    logger.info("- " + c);
                }
                account.setContact(newContact);
            }

            engine.updateAccount(account);

            // TODO: if account is deactivated, cancel all account's pending operations
        }

        // RFC 8555 Section 7.1.2.1 Orders List
        //
        // Each account object includes an "orders" URL from which a list of
        // orders created by the account can be fetched via POST-as-GET request.

        URI ordersURL = uriInfo.getBaseUriBuilder().path("acct").path(accountID).path("orders").build();
        account.setOrders(ordersURL);

        ResponseBuilder builder = Response.ok(account);

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getID());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        builder.entity(account);

        return builder.build();
    }
}

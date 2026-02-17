//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAccountOrders;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME account management endpoint (RFC 8555 Section 7.3).
 *
 * @author Endi S. Dewata (original)
 */
@Path("acct")
@ACMEProtocolEndpoint
public class ACMEAccountResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMEAccountResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @POST
    @Path("{accountID}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateAccount(@PathParam("accountID") String accountID, String requestData) throws Exception {

        logger.info("Updating account " + accountID);

        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);
        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        engine.validateNonce(header.getNonce());

        URI kid = header.getKid();
        String kidPath = kid.getPath();
        String jwsAccountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);

        if (!accountID.equals(jwsAccountID)) {
            throw new Exception("Invalid KID: " + kid);
        }

        ACMEAccount account = engine.getAccount(accountID);
        engine.validateJWS(jws, header.getAlg(), account.getJWK());

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");

        if (payload.isEmpty()) {
            logger.info("Empty payload; treating as POST-as-GET");
        } else {
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
                account.setContact(newContact);
            }

            engine.updateAccount(account);
        }

        String baseUri = getBaseUri();
        account.setOrders(new URI(baseUri + "/acct/" + accountID + "/orders"));

        ACMENonce nonce = engine.createNonce();

        return Response.ok(account.toJSON())
                .header("Replay-Nonce", nonce.getID())
                .header("Link", getIndexLink())
                .build();
    }

    @POST
    @Path("{accountID}/orders")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAccountOrders(@PathParam("accountID") String accountID, String requestData) throws Exception {

        logger.info("Retrieving orders for account " + accountID);

        ACMEAccount account = engine.getAccount(accountID);

        Collection<ACMEOrder> orders = engine.getOrdersByAccount(account);
        String baseUri = getBaseUri();

        Collection<URI> orderURLs = new ArrayList<>();
        for (ACMEOrder order : orders) {
            if ("invalid".equals(order.getStatus())) continue;
            orderURLs.add(new URI(baseUri + "/order/" + order.getID()));
        }

        ACMEAccountOrders accountOrders = new ACMEAccountOrders();
        accountOrders.setOrders(orderURLs);

        ACMENonce nonce = engine.createNonce();

        return Response.ok(accountOrders.toJSON())
                .header("Replay-Nonce", nonce.getID())
                .header("Link", getIndexLink())
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

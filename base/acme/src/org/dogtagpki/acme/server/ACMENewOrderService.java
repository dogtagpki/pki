//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.util.ArrayList;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACME;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;

/**
 * @author Endi S. Dewata
 */
@Path("new-order")
public class ACMENewOrderService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMENewOrderService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response createNewOrder(JWS jws) throws Exception {

        logger.info("Creating new order");

        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
        engine.validateNonce(header.getNonce());

        URI kid = header.getKid();
        String kidPath = kid.getPath();
        String accountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);
        logger.info("Account ID: " + accountID);

        ACMEAccount account = engine.getAccount(accountID);
        engine.validateJWS(jws, header.getAlg(), account.getJWK());

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        ACMEOrder request = ACMEOrder.fromJSON(payload);
        ArrayList<URI> authzURLs = new ArrayList<>();

        logger.info("Generating authorization for each identifiers");
        for (ACMEIdentifier identifier : request.getIdentifiers()) {

            logger.info("Identifier " + identifier.getType() + ": " + identifier.getValue());

            String authzID = ACME.randomAlphanumeric(10);
            logger.info("- authorization ID: " + authzID);

            ACMEAuthorization authorization = new ACMEAuthorization();
            authorization.setID(authzID);
            authorization.setStatus("pending");
            authorization.setIdentifier(identifier);

            engine.addAuthorization(account, authorization);

            URI authzURI = uriInfo.getBaseUriBuilder().path("authz").path(authzID).build();
            authzURLs.add(authzURI);
        }

        String orderID = ACME.randomAlphanumeric(10);
        logger.info("Order ID: " + orderID);

        ACMEOrder order = new ACMEOrder();
        order.setID(orderID);
        order.setStatus("pending");
        order.setIdentifiers(request.getIdentifiers());
        order.setNotBefore(request.getNotBefore());
        order.setNotAfter(request.getNotAfter());

        order.setAuthorizations(authzURLs.toArray(new URI[authzURLs.size()]));

        URI finalizeURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).path("finalize").build();
        order.setFinalize(finalizeURL);

        engine.addOrder(account, order);

        URI orderURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).build();
        ResponseBuilder builder = Response.created(orderURL);

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getValue());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        builder.entity(order);

        return builder.build();
    }
}

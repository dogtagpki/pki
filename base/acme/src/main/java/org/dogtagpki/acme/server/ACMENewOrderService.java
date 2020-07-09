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
import org.dogtagpki.acme.ACMEPolicy;
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
        ArrayList<String> authzIDs = new ArrayList<>();

        logger.info("Generating authorization for each identifiers");
        for (ACMEIdentifier identifier : request.getIdentifiers()) {

            String type = identifier.getType();
            String value = identifier.getValue();
            logger.info("Identifier " + type + ": " + value);

            engine.getPolicy().validateIdentifier(identifier);

            // RFC 8555 Section 7.1.3: Order Objects
            //
            // Any identifier of type "dns" in a newOrder request MAY have a
            // wildcard domain name as its value.  A wildcard domain name consists
            // of a single asterisk character followed by a single full stop
            // character ("*.") followed by a domain name as defined for use in the
            // Subject Alternate Name Extension by [RFC5280].  An authorization
            // returned by the server for a wildcard domain name identifier MUST NOT
            // include the asterisk and full stop ("*.") prefix in the authorization
            // identifier value.  The returned authorization MUST include the
            // optional "wildcard" field, with a value of true.

            boolean wildcard;
            if ("dns".equals(type) && value.startsWith("*.")) {
                wildcard = true;
                value = value.substring(2); // remove *. prefix
            } else {
                wildcard = false;
            }

            // store identifier for authorization without *. prefix
            identifier = new ACMEIdentifier();
            identifier.setType(type);
            identifier.setValue(value);

            String authzID = ACME.randomAlphanumeric(10);
            logger.info("- authorization ID: " + authzID);

            ACMEAuthorization authorization = new ACMEAuthorization();
            authorization.setID(authzID);
            authorization.setIdentifier(identifier);
            authorization.setWildcard(wildcard);

            authorization.setStatus("pending");
            authorization.setExpirationTime(null);

            engine.addAuthorization(account, authorization);

            authzIDs.add(authzID);
        }

        String orderID = ACME.randomAlphanumeric(10);
        logger.info("Order ID: " + orderID);

        ACMEOrder order = new ACMEOrder();
        order.setID(orderID);
        order.setStatus("pending");
        order.setIdentifiers(request.getIdentifiers());
        order.setNotBefore(request.getNotBefore());
        order.setNotAfter(request.getNotAfter());

        order.setAuthzIDs(authzIDs.toArray(new String[authzIDs.size()]));

        engine.addOrder(account, order);

        ArrayList<URI> authzURLs = new ArrayList<>();
        for (String authzID : authzIDs) {
            URI authzURI = uriInfo.getBaseUriBuilder().path("authz").path(authzID).build();
            authzURLs.add(authzURI);
        }
        order.setAuthorizations(authzURLs.toArray(new URI[authzURLs.size()]));

        URI finalizeURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).path("finalize").build();
        order.setFinalize(finalizeURL);

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

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
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;

/**
 * @author Endi S. Dewata
 */
@Path("order/{id}")
@ACMEManagedService
public class ACMEOrderService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEOrderService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST(@PathParam("id") String orderID, JWS jws) throws Exception {

        logger.info("Retrieving order " + orderID);

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

        ACMEOrder order = engine.getOrder(account, orderID);

        String[] authzIDs = order.getAuthzIDs();
        if (authzIDs != null) {
            ArrayList<URI> authzURLs = new ArrayList<>();
            for (String authzID : authzIDs) {
                URI authzURI = uriInfo.getBaseUriBuilder().path("authz").path(authzID).build();
                authzURLs.add(authzURI);
            }
            order.setAuthorizations(authzURLs.toArray(new URI[authzURLs.size()]));
        }

        URI finalizeURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).path("finalize").build();
        order.setFinalize(finalizeURL);

        String certID = order.getCertID();
        if (certID != null) {
            URI certURL = uriInfo.getBaseUriBuilder().path("cert").path(certID).build();
            order.setCertificate(certURL);
        }

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getID());

        URI indexURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(indexURL, "index");

        builder.entity(order);

        return builder.build();
    }
}

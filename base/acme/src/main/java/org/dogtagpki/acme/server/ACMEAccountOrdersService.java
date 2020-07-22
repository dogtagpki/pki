//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;

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
import org.dogtagpki.acme.ACMEAccountOrders;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;

/**
 * RFC 8555 Section 7.1.2.1 Orders List
 *
 * Each account object includes an "orders" URL from which a list of
 * orders created by the account can be fetched via POST-as-GET request.
 * The result of the request MUST be a JSON object whose "orders" field
 * is an array of URLs, each identifying an order belonging to the
 * account.
 *
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Link: <https://example.com/acme/directory>;rel="index"
 * Link: <https://example.com/acme/orders/rzGoeA?cursor=2>;rel="next"
 *
 * {
 *   "orders": [
 *     "https://example.com/acme/order/TOlocE8rfgo",
 *     "https://example.com/acme/order/4E16bbL5iSw",
 *     ...
 *     "https://example.com/acme/order/neBHYLfw0mg"
 *   ]
 * }
 *
 * @author Endi S. Dewata
 */
@Path("acct/{id}/orders")
public class ACMEAccountOrdersService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEAccountOrdersService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAccountOrders(@PathParam("id") String accountID) throws Exception {

        logger.info("Retrieving orders for account " + accountID);

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEAccount account = engine.getAccount(accountID);

        // RFC 8555 Section 7.1.2.1 Orders List
        //
        // The server SHOULD include pending orders and SHOULD NOT
        // include orders that are invalid in the array of URLs.

        Collection<ACMEOrder> orders = engine.getOrdersByAccount(account);

        Collection<URI> orderURLs = new ArrayList<>();
        for (ACMEOrder order : orders) {

            if ("invalid".equals(order.getStatus())) continue;

            URI orderURL = uriInfo.getBaseUriBuilder().path("order").path(order.getID()).build();
            logger.info("- " + orderURL);

            orderURLs.add(orderURL);
        }

        ACMEAccountOrders accountOrders = new ACMEAccountOrders();
        accountOrders.setOrders(orderURLs);

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getID());

        URI indexURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(indexURL, "index");

        builder.entity(accountOrders);

        return builder.build();
    }
}

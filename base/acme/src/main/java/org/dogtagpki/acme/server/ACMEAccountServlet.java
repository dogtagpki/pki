//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.PrintWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.http.client.utils.URIBuilder;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAccountOrders;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME account.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeAccountServlet",
        urlPatterns = "/acct/*")
public class ACMEAccountServlet extends ACMEServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMEChallengeServlet.class);

    @WebAction(method = HttpMethod.POST, paths = { "{}"})
    public void updateAccount(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String accountID = pathElement[0];
        logger.info("Updating account " + accountID);

        String requestData = request.getReader().lines().collect(Collectors.joining());
        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);

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
        URIBuilder uriBuilder = new URIBuilder(request.getRequestURL().toString());
        uriBuilder.removeQuery();

        uriBuilder.setPath(request.getContextPath() + "/acct/" + accountID + "/orders");
        account.setOrders(uriBuilder.build());

        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());

        addIndex(request, response);

        PrintWriter out = response.getWriter();
        out.println(account.toJSON());
    }

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
    @WebAction(method = HttpMethod.POST, paths = { "{}/orders"})
    public void getAccountOrders(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String accountID = pathElement[0];
        logger.info("Retrieving orders for account " + accountID);

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEAccount account = engine.getAccount(accountID);

        // RFC 8555 Section 7.1.2.1 Orders List
        //
        // The server SHOULD include pending orders and SHOULD NOT
        // include orders that are invalid in the array of URLs.

        Collection<ACMEOrder> orders = engine.getOrdersByAccount(account);
        URIBuilder uriBuilder = new URIBuilder(request.getRequestURL().toString());
        uriBuilder.removeQuery();


        Collection<URI> orderURLs = new ArrayList<>();
        for (ACMEOrder order : orders) {

            if ("invalid".equals(order.getStatus())) continue;

            uriBuilder.setPath(request.getContextPath() + "/order/" + order.getID());

            logger.info("- " + uriBuilder);

            orderURLs.add(uriBuilder.build());
        }

        ACMEAccountOrders accountOrders = new ACMEAccountOrders();
        accountOrders.setOrders(orderURLs);

        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());

        addIndex(request, response);

        PrintWriter out = response.getWriter();
        out.println(accountOrders.toJSON());
    }
}

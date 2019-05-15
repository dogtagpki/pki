// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.acme;

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

import org.apache.commons.lang.RandomStringUtils;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;

import com.fasterxml.jackson.databind.ObjectMapper;

@Path("new-order")
public class ACMENewOrderService {

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response createNewOrder(JWS jws) throws Exception {

        String payload = new String(jws.getDecodedPayload(), "UTF-8");

        System.out.println("JWS Protected Header: " + jws.getDecodedProtectedHeader());
        System.out.println("JWS Payload: " + payload);
        System.out.println("JWS Signature: " + jws.getDecodedSignature());

        ObjectMapper mapper = new ObjectMapper();
        ACMEOrder request = mapper.readValue(payload, ACMEOrder.class);

        ACMEDatabase database = ACMEDatabase.getInstance();
        String orderID = RandomStringUtils.randomAlphanumeric(10);

        ACMEOrder order = new ACMEOrder();
        order.setStatus("pending");
        order.setExpires("2016-01-05T14:09:07.99Z");
        order.setIdentifiers(request.getIdentifiers());
        order.setNotBefore(request.getNotBefore());
        order.setNotAfter(request.getNotAfter());

        ArrayList<URI> authzURLs = new ArrayList<>();

        System.out.println("Identifiers:");
        for (ACMEIdentifier identifier : order.getIdentifiers()) {
            System.out.println("- " + identifier.getType() + ": " + identifier.getValue());

            String authzID = RandomStringUtils.randomAlphanumeric(10);

            ACMEAuthorization authorization = new ACMEAuthorization();
            authorization.setStatus("pending");
            authorization.setExpires("2016-01-05T14:09:07.99Z");
            authorization.setIdentifier(identifier);
            database.addAuthorization(authzID, authorization);

            URI authzURI = uriInfo.getBaseUriBuilder().path("authz").path(authzID).build();
            authzURLs.add(authzURI);
        }

        order.setAuthorizations(authzURLs.toArray(new URI[authzURLs.size()]));
        database.addOrder(orderID, order);

        URI finalizeURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).path("finalize").build();
        order.setFinalize(finalizeURL);

        URI orderURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).build();
        ResponseBuilder builder = Response.created(orderURL);

        builder.header("Replay-Nonce", "MYAuvOpaoIiywTezizk5vw");

        URI link = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(link, "index");

        builder.entity(order);

        return builder.build();
    }
}

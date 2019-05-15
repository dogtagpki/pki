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

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.RandomStringUtils;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;

import com.fasterxml.jackson.databind.ObjectMapper;

@Path("order/{id}/finalize")
public class ACMEFinalizeOrderService {

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST(@PathParam("id") String orderID, JWS jws) throws Exception {

        System.out.println("Order ID: " + orderID);

        ACMEDatabase database = ACMEDatabase.getInstance();
        ACMEOrder order = database.getOrder(orderID);

        String payload = new String(jws.getDecodedPayload(), "UTF-8");

        System.out.println("JWS Protected Header: " + jws.getDecodedProtectedHeader());
        System.out.println("JWS Payload: " + payload);
        System.out.println("JWS Signature: " + jws.getDecodedSignature());

        ObjectMapper mapper = new ObjectMapper();
        ACMEOrder request = mapper.readValue(payload, ACMEOrder.class);

        System.out.println("CSR: " + request.getCSR());

        String certID = RandomStringUtils.randomAlphanumeric(10);
        URI certURL = uriInfo.getBaseUriBuilder().path("cert").path(certID).build();

        order.setStatus("valid");
        order.setCertificate(certURL);

        ResponseBuilder builder = Response.ok();

        builder.header("Replay-Nonce", "MYAuvOpaoIiywTezizk5vw");

        URI link = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(link, "index");

        builder.entity(order);

        return builder.build();
    }
}

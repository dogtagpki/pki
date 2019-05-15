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
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.JWS;

import com.fasterxml.jackson.databind.ObjectMapper;

@Path("new-account")
public class ACMENewAccountService {

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response createNewAccount(JWS jws) throws Exception {

        String payload = new String(jws.getDecodedPayload(), "UTF-8");

        ObjectMapper mapper = new ObjectMapper();
        ACMEAccount request = mapper.readValue(payload, ACMEAccount.class);

        URI accountURL = uriInfo.getBaseUriBuilder().path("acct").path("evOfKhNU60wg").build();
        URI ordersURL = uriInfo.getBaseUriBuilder().path("acct").path("evOfKhNU60wg").path("orders").build();

        ACMEAccount response = new ACMEAccount();
        response.setStatus("valid");
        response.setContact(request.getContact());
        response.setOrders(ordersURL);

        ResponseBuilder builder = Response.created(accountURL);

        builder.header("Replay-Nonce", "D8s4D2mLs8Vn-goWuPQeKA");

        URI link = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(link, "index");

        builder.entity(response);

        return builder.build();
    }
}

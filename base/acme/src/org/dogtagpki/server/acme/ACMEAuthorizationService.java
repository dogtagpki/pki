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
import java.security.SecureRandom;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.JWS;

@Path("authz/{id}")
public class ACMEAuthorizationService {

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST(@PathParam("id") String id, JWS jws) throws Exception {

        System.out.println("Authorization ID: " + id);

        ACMEDatabase database = ACMEDatabase.getInstance();
        ACMEAuthorization authorization = database.getAuthorization(id);

        String payload = new String(jws.getDecodedPayload(), "UTF-8");

        System.out.println("JWS Protected Header: " + jws.getDecodedProtectedHeader());
        System.out.println("JWS Payload: " + payload);
        System.out.println("JWS Signature: " + jws.getDecodedSignature());

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        String token = Base64.encodeBase64String(bytes);

        String httpChallengeID = RandomStringUtils.randomAlphanumeric(10);

        ACMEChallenge httpChallenge = new ACMEChallenge();
        httpChallenge.setType("http-01");
        httpChallenge.setURL(uriInfo.getBaseUriBuilder().path("chall").path(httpChallengeID).build());
        httpChallenge.setToken(token);

        String dnsChallengeID = RandomStringUtils.randomAlphanumeric(10);

        ACMEChallenge dnsChallenge = new ACMEChallenge();
        dnsChallenge.setType("dns-01");
        dnsChallenge.setURL(uriInfo.getBaseUriBuilder().path("chall").path(dnsChallengeID).build());
        dnsChallenge.setToken(token);

        authorization.setChallenges(new ACMEChallenge[] {
                httpChallenge, dnsChallenge
        });

        database.addChallenge(id, httpChallengeID, httpChallenge);
        database.addChallenge(id, dnsChallengeID, dnsChallenge);

        ResponseBuilder builder = Response.ok();

        builder.header("Replay-Nonce", "MYAuvOpaoIiywTezizk5vw");

        URI link = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(link, "index");

        builder.entity(authorization);

        return builder.build();
    }
}

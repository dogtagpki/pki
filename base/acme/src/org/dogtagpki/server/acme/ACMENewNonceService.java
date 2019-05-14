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

import javax.ws.rs.GET;
import javax.ws.rs.HEAD;
import javax.ws.rs.Path;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

@Path("new-nonce")
public class ACMENewNonceService {

    @Context
    UriInfo uriInfo;

    @HEAD
    public Response headNewNonce() {
        ResponseBuilder builder = Response.ok();
        updateResponseBuilder(builder);
        return builder.build();
    }

    @GET
    public Response getNewNonce() {
        ResponseBuilder builder = Response.noContent();
        updateResponseBuilder(builder);
        return builder.build();
    }

    public void updateResponseBuilder(ResponseBuilder builder) {

        builder.header("Replay-Nonce", "oFvnlFP1wIhRlYS2jTaXbA");

        CacheControl cc = new CacheControl();
        cc.setNoStore(true);
        builder.cacheControl(cc);

        URI link = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(link, "index");
    }
}

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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.tps.cert;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;


/**
 * @author Endi S. Dewata
 */
@Path("certs")
public interface TPSCertResource {

    @GET
    @ClientResponseType(entityType=TPSCertCollection.class)
    public Response findCerts(
            @QueryParam("filter") String filter,
            @QueryParam("tokenID") String tokenID,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{certID}")
    @ClientResponseType(entityType=TPSCertData.class)
    public Response getCert(@PathParam("certID") String certID);
}

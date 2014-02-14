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
package com.netscape.certsrv.tps.authenticator;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;


/**
 * @author Endi S. Dewata
 */
@Path("authenticators")
@AuthMethodMapping("authenticators")
@ACLMapping("authenticators.read")
public interface AuthenticatorResource {

    @GET
    @ClientResponseType(entityType=AuthenticatorCollection.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response findAuthenticators(
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{authenticatorID}")
    @ClientResponseType(entityType=AuthenticatorData.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response getAuthenticator(@PathParam("authenticatorID") String authenticatorID);

    @POST
    @ACLMapping("authenticators.add")
    @ClientResponseType(entityType=AuthenticatorData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response addAuthenticator(AuthenticatorData authenticatorData);

    @PUT
    @Path("{authenticatorID}")
    @ACLMapping("authenticators.modify")
    @ClientResponseType(entityType=AuthenticatorData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response updateAuthenticator(
            @PathParam("authenticatorID") String authenticatorID,
            AuthenticatorData authenticatorData);

    @POST
    @Path("{authenticatorID}")
    @ACLMapping("authenticators.approve")
    @ClientResponseType(entityType=AuthenticatorData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response changeAuthenticatorStatus(
            @PathParam("authenticatorID") String authenticatorID,
            @QueryParam("action") String action);

    @DELETE
    @Path("{authenticatorID}")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("authenticators.remove")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response removeAuthenticator(@PathParam("authenticatorID") String authenticatorID);
}

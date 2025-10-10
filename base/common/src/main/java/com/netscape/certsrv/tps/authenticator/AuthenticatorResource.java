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

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.base.PATCH;


/**
 * @author Endi S. Dewata
 */
@Path("authenticators")
@AuthMethodMapping("authenticators")
@ACLMapping("authenticators.read")
public interface AuthenticatorResource {

    @GET
    public Response findAuthenticators(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{authenticatorID}")
    public Response getAuthenticator(@PathParam("authenticatorID") String authenticatorID);

    @POST
    @ACLMapping("authenticators.add")
    public Response addAuthenticator(AuthenticatorData authenticatorData);

    @PATCH
    @Path("{authenticatorID}")
    @ACLMapping("authenticators.modify")
    public Response updateAuthenticator(
            @PathParam("authenticatorID") String authenticatorID,
            AuthenticatorData authenticatorData);

    @POST
    @Path("{authenticatorID}")
    @ACLMapping("authenticators.change-status")
    public Response changeStatus(
            @PathParam("authenticatorID") String authenticatorID,
            @QueryParam("action") String action);

    @DELETE
    @Path("{authenticatorID}")
    @ACLMapping("authenticators.remove")
    public Response removeAuthenticator(@PathParam("authenticatorID") String authenticatorID);
}

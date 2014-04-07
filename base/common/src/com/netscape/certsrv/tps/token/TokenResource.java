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
package com.netscape.certsrv.tps.token;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.base.PATCH;


/**
 * @author Endi S. Dewata
 */
@Path("tokens")
@AuthMethodMapping("tokens")
@ACLMapping("tokens.read")
public interface TokenResource {

    @GET
    @ClientResponseType(entityType=TokenCollection.class)
    public Response findTokens(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{tokenID}")
    @ClientResponseType(entityType=TokenData.class)
    public Response getToken(@PathParam("tokenID") String tokenID);

    @POST
    @ClientResponseType(entityType=TokenData.class)
    @ACLMapping("tokens.add")
    public Response addToken(TokenData tokenData);

    @PUT
    @Path("{tokenID}")
    @ClientResponseType(entityType=TokenData.class)
    @ACLMapping("tokens.modify")
    public Response replaceToken(
            @PathParam("tokenID") String tokenID,
            TokenData tokenData);

    @PATCH
    @Path("{tokenID}")
    @ClientResponseType(entityType=TokenData.class)
    @ACLMapping("tokens.modify")
    public Response modifyToken(
            @PathParam("tokenID") String tokenID,
            TokenData tokenData);

    @POST
    @Path("{tokenID}")
    @ClientResponseType(entityType=TokenData.class)
    @ACLMapping("tokens.modify")
    public Response changeTokenStatus(
            @PathParam("tokenID") String tokenID,
            @QueryParam("status") TokenStatus tokenStatus);

    @DELETE
    @Path("{tokenID}")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("tokens.remove")
    public Response removeToken(@PathParam("tokenID") String tokenID);
}

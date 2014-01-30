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
package com.netscape.certsrv.tps.connection;

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


/**
 * @author Endi S. Dewata
 */
@Path("connections")
@AuthMethodMapping("connections")
@ACLMapping("connections.read")
public interface ConnectionResource {

    @GET
    @ClientResponseType(entityType=ConnectionCollection.class)
    public Response findConnections(
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{connectionID}")
    @ClientResponseType(entityType=ConnectionData.class)
    public Response getConnection(@PathParam("connectionID") String connectionID);

    @POST
    @ACLMapping("connections.add")
    @ClientResponseType(entityType=ConnectionData.class)
    public Response addConnection(ConnectionData connectionData);

    @PUT
    @Path("{connectionID}")
    @ACLMapping("connections.modify")
    @ClientResponseType(entityType=ConnectionData.class)
    public Response updateConnection(
            @PathParam("connectionID") String connectionID,
            ConnectionData connectionData);

    @POST
    @Path("{connectionID}")
    @ACLMapping("connections.approve")
    @ClientResponseType(entityType=ConnectionData.class)
    public Response changeConnectionStatus(
            @PathParam("connectionID") String connectionID,
            @QueryParam("action") String action);

    @DELETE
    @Path("{connectionID}")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("connections.remove")
    public Response removeConnection(@PathParam("connectionID") String connectionID);
}

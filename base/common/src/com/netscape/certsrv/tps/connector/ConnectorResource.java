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
package com.netscape.certsrv.tps.connector;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.base.PATCH;


/**
 * @author Endi S. Dewata
 */
@Path("connectors")
@AuthMethodMapping("connectors")
@ACLMapping("connectors.read")
public interface ConnectorResource {

    @GET
    public Response findConnectors(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{connectorID}")
    public Response getConnector(@PathParam("connectorID") String connectorID);

    @POST
    @ACLMapping("connectors.add")
    public Response addConnector(ConnectorData connectorData);

    @PATCH
    @Path("{connectorID}")
    @ACLMapping("connectors.modify")
    public Response updateConnector(
            @PathParam("connectorID") String connectorID,
            ConnectorData connectorData);

    @POST
    @Path("{connectorID}")
    @ACLMapping("connectors.change-status")
    public Response changeStatus(
            @PathParam("connectorID") String connectorID,
            @QueryParam("action") String action);

    @DELETE
    @Path("{connectorID}")
    @ACLMapping("connectors.remove")
    public Response removeConnector(@PathParam("connectorID") String connectorID);
}

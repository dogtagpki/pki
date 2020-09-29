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
package com.netscape.certsrv.system;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;

/**
 * @author Ade Lee
 */
@Path("/admin/tps-connectors")
@AuthMethodMapping("tpsconnectors")
public interface TPSConnectorResource {
    @GET
    public Response findConnectors(
            @QueryParam("host") String host,
            @QueryParam("port") String port,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{id}")
    public Response getConnector(@PathParam("id") String id);

    @POST
    public Response createConnector(@QueryParam("host") String host,
            @QueryParam("port") String port);

    @POST
    @Path("{id}")
    public Response modifyConnector(@PathParam("id") String id, TPSConnectorData data);

    @DELETE
    @Path("{id}")
    public Response deleteConnector(@PathParam("id") String id);

    @POST
    @Path("{id}/shared-secret")
    @ACLMapping("admin.sharedsecret")
    public Response createSharedSecret(@PathParam("id") String id);

    @PUT
    @Path("{id}/shared-secret")
    @ACLMapping("admin.sharedsecret")
    public Response replaceSharedSecret(@PathParam("id") String id);

    @DELETE
    @Path("{id}/shared-secret")
    @ACLMapping("admin.sharedsecret")
    public Response deleteSharedSecret(@PathParam("id") String id);

    @DELETE
    public Response deleteConnector(@QueryParam("host") String host,
            @QueryParam("port") String port);

    @GET
    @Path("{id}/shared-secret")
    @ACLMapping("admin.sharedsecret")
    public Response getSharedSecret(@PathParam("id") String id);
}

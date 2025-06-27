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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.system;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;

/**
 * @author alee
 * @author Endi S. Dewata
 */
@Path("securityDomain")
public interface SecurityDomainResource {

    @GET
    @Path("installToken")
    @ACLMapping("securityDomain.read")
    @AuthMethodMapping("securityDomain.installToken")
    public Response getInstallToken(
            @QueryParam("hostname") String hostname,
            @QueryParam("subsystem") String subsystem);

    @GET
    @Path("domainInfo")
    public Response getDomainInfo();

    @GET
    @Path("hosts")
    public Response getHosts();

    @GET
    @Path("hosts/{hostID}")
    public Response getHost(@PathParam("hostID") String hostID);

    @PUT
    @Path("hosts")
    @ACLMapping("securityDomain.modify")
    public Response addHost(SecurityDomainHost host);

    @DELETE
    @Path("hosts/{hostID}")
    @ACLMapping("securityDomain.modify")
    public Response removeHost(@PathParam("hostID") String hostID);
}

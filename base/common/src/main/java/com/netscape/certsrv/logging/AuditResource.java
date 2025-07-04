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
package com.netscape.certsrv.logging;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.base.PATCH;


/**
 * @author Endi S. Dewata
 */
@Path("audit")
@AuthMethodMapping("audit")
public interface AuditResource {

    @GET
    @ACLMapping("audit.read")
    public Response getAuditConfig();

    @PATCH
    @ACLMapping("audit.modify")
    public Response updateAuditConfig(AuditConfig configData);

    @POST
    @ACLMapping("audit.modify")
    public Response changeAuditStatus(
            @QueryParam("action") String action);

    @GET
    @Path("files")
    @ACLMapping("audit-log.read")
    public Response findAuditFiles();

    @GET
    @Path("files/{filename}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @ACLMapping("audit-log.read")
    public Response getAuditFile(@PathParam("filename") String filename);
}

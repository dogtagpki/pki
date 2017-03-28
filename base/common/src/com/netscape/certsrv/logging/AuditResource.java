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

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;

import org.jboss.resteasy.annotations.ClientResponseType;

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
    @ClientResponseType(entityType=AuditConfig.class)
    @ACLMapping("audit.read")
    public Response getAuditConfig();

    @PATCH
    @ClientResponseType(entityType=AuditConfig.class)
    @ACLMapping("audit.modify")
    public Response updateAuditConfig(AuditConfig configData);

    @POST
    @ClientResponseType(entityType=AuditConfig.class)
    @ACLMapping("audit.modify")
    public Response changeAuditStatus(
            @QueryParam("action") String action);

    @GET
    @Path("files")
    @ClientResponseType(entityType=AuditFileCollection.class)
    @ACLMapping("audit-log.read")
    public Response findAuditFiles();

    @POST
    @Path("files/{filename}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @ClientResponseType(entityType=StreamingOutput.class)
    @ACLMapping("audit-log.read")
    public Response getAuditFile(@PathParam("filename") String filename);

    @DELETE
    @Path("files/{filename}")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("audit.modify")
    public Response removeAuditFile(@PathParam("filename") String filename);

    @POST
    @Path("logs")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @ClientResponseType(entityType=StreamingOutput.class)
    @ACLMapping("audit-log.read")
    public Response findAuditLogs(AuditLogFindRequest request) throws Exception;
}

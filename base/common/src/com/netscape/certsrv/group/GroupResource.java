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

package com.netscape.certsrv.group;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
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
@Path("admin/groups")
@ACLMapping("groups")
@AuthMethodMapping("groups")
public interface GroupResource {

    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public GroupCollection findGroups(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @ClientResponseType(entityType=GroupData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response addGroup(GroupData groupData);

    @GET
    @Path("{groupID}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public GroupData getGroup(@PathParam("groupID") String groupID);

    @POST
    @Path("{groupID}")
    @ClientResponseType(entityType=GroupData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response modifyGroup(@PathParam("groupID") String groupID, GroupData groupData);

    @DELETE
    @Path("{groupID}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void removeGroup(@PathParam("groupID") String groupID);

    @GET
    @Path("{groupID}/members")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public GroupMemberCollection findGroupMembers(
            @PathParam("groupID") String groupID,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @Path("{groupID}/members")
    @ClientResponseType(entityType=GroupMemberData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response addGroupMember(@PathParam("groupID") String groupID, String memberID);

    @GET
    @Path("{groupID}/members/{memberID}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public GroupMemberData getGroupMember(@PathParam("groupID") String groupID, @PathParam("memberID") String memberID);

    @DELETE
    @Path("{groupID}/members/{memberID}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void removeGroupMember(@PathParam("groupID") String groupID, @PathParam("memberID") String memberID);
}

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

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
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
@Path("admin/groups")
@ACLMapping("groups")
@AuthMethodMapping("groups")
public interface GroupResource {

    @GET
    @ClientResponseType(entityType=GroupCollection.class)
    public Response findGroups(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @ClientResponseType(entityType=GroupData.class)
    public Response addGroup(GroupData groupData);

    @GET
    @Path("{groupID}")
    @ClientResponseType(entityType=GroupData.class)
    public Response getGroup(@PathParam("groupID") String groupID);

    @PATCH
    @Path("{groupID}")
    @ClientResponseType(entityType=GroupData.class)
    public Response modifyGroup(@PathParam("groupID") String groupID, GroupData groupData);

    @DELETE
    @Path("{groupID}")
    @ClientResponseType(entityType=Void.class)
    public Response removeGroup(@PathParam("groupID") String groupID);

    @GET
    @Path("{groupID}/members")
    @ClientResponseType(entityType=GroupMemberCollection.class)
    public Response findGroupMembers(
            @PathParam("groupID") String groupID,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @Path("{groupID}/members")
    @ClientResponseType(entityType=GroupMemberData.class)
    public Response addGroupMember(@PathParam("groupID") String groupID, GroupMemberData groupMemberData);

    @GET
    @Path("{groupID}/members/{memberID}")
    @ClientResponseType(entityType=GroupMemberData.class)
    public Response getGroupMember(@PathParam("groupID") String groupID, @PathParam("memberID") String memberID);

    @DELETE
    @Path("{groupID}/members/{memberID}")
    @ClientResponseType(entityType=Void.class)
    public Response removeGroupMember(@PathParam("groupID") String groupID, @PathParam("memberID") String memberID);
}

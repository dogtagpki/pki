//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.rest.base.GroupBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.group.GroupCollection;
import com.netscape.certsrv.group.GroupData;
import com.netscape.certsrv.group.GroupMemberCollection;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * JAX-RS resource for CA group operations.
 * Replaces CAGroupServlet.
 */
@Path("v2/admin/groups")
public class CAGroupResource {

    private static final Logger logger = LoggerFactory.getLogger(CAGroupResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findGroups(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        GroupBase groupBase = new GroupBase(engine);
        GroupCollection groups = groupBase.findGroups(filter, start, size);
        return Response.ok(groups.toJSON()).build();
    }

    @GET
    @Path("{groupId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGroup(@PathParam("groupId") String groupId) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        GroupBase groupBase = new GroupBase(engine);
        GroupData group = groupBase.getGroup(groupId);
        return Response.ok(group.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addGroup(String requestData) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        GroupBase groupBase = new GroupBase(engine);
        GroupData groupData = JSONSerializer.fromJSON(requestData, GroupData.class);
        GroupData newGroup = groupBase.addGroup(groupData);
        return Response.status(Response.Status.CREATED).entity(newGroup.toJSON()).build();
    }

    @DELETE
    @Path("{groupId}")
    public Response removeGroup(@PathParam("groupId") String groupId) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        GroupBase groupBase = new GroupBase(engine);
        groupBase.removeGroup(groupId);
        return Response.noContent().build();
    }

    @GET
    @Path("{groupId}/members")
    @Produces(MediaType.APPLICATION_JSON)
    public Response findGroupMembers(
            @PathParam("groupId") String groupId,
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        GroupBase groupBase = new GroupBase(engine);
        GroupMemberCollection members = groupBase.findGroupMembers(groupId, filter, start, size);
        return Response.ok(members.toJSON()).build();
    }

    @POST
    @Path("{groupId}/members")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addGroupMember(
            @PathParam("groupId") String groupId,
            String requestData) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        GroupBase groupBase = new GroupBase(engine);
        GroupMemberData memberData = JSONSerializer.fromJSON(requestData, GroupMemberData.class);
        GroupMemberData newMember = groupBase.addGroupMember(groupId, memberData);
        return Response.status(Response.Status.CREATED).entity(newMember.toJSON()).build();
    }

    @DELETE
    @Path("{groupId}/members/{memberId}")
    public Response removeGroupMember(
            @PathParam("groupId") String groupId,
            @PathParam("memberId") String memberId) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        GroupBase groupBase = new GroupBase(engine);
        groupBase.removeGroupMember(groupId, memberId);
        return Response.noContent().build();
    }
}

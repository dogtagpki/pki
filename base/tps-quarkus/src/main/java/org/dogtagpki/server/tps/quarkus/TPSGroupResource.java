//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.net.URLEncoder;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.server.rest.base.GroupServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.group.GroupCollection;
import com.netscape.certsrv.group.GroupData;
import com.netscape.certsrv.group.GroupMemberCollection;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.util.JSONSerializer;

@Path("v2/admin/groups")
public class TPSGroupResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSGroupResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Context
    UriInfo uriInfo;

    private GroupServletBase createBase() {
        return new GroupServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findGroups(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSGroupResource.findGroups()");
        GroupCollection groups = createBase().findGroups(filter, start, size);
        return Response.ok(groups.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addGroup(String requestData) throws Exception {
        logger.debug("TPSGroupResource.addGroup()");
        GroupData data = JSONSerializer.fromJSON(requestData, GroupData.class);
        GroupData group = createBase().addGroup(data);
        String encodedID = URLEncoder.encode(group.getGroupID(), "UTF-8");
        java.net.URI location = uriInfo.getAbsolutePathBuilder().path(encodedID).build();
        return Response.created(location).entity(group.toJSON()).build();
    }

    @GET
    @Path("{groupId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGroup(@PathParam("groupId") String groupId) throws Exception {
        logger.debug("TPSGroupResource.getGroup(): groupId={}", groupId);
        GroupData group = createBase().getGroup(groupId);
        return Response.ok(group.toJSON()).build();
    }

    @PATCH
    @Path("{groupId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyGroup(@PathParam("groupId") String groupId, String requestData) throws Exception {
        logger.debug("TPSGroupResource.modifyGroup(): groupId={}", groupId);
        GroupData data = JSONSerializer.fromJSON(requestData, GroupData.class);
        GroupData group = createBase().modifyGroup(groupId, data);
        return Response.ok(group.toJSON()).build();
    }

    @DELETE
    @Path("{groupId}")
    public Response removeGroup(@PathParam("groupId") String groupId) throws Exception {
        logger.debug("TPSGroupResource.removeGroup(): groupId={}", groupId);
        createBase().removeGroup(groupId);
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
        logger.debug("TPSGroupResource.findGroupMembers(): groupId={}", groupId);
        GroupMemberCollection members = createBase().findGroupMembers(groupId, filter, start, size);
        return Response.ok(members.toJSON()).build();
    }

    @POST
    @Path("{groupId}/members")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addGroupMember(@PathParam("groupId") String groupId, String requestData) throws Exception {
        logger.debug("TPSGroupResource.addGroupMember(): groupId={}", groupId);
        GroupMemberData data = JSONSerializer.fromJSON(requestData, GroupMemberData.class);
        GroupMemberData member = createBase().addGroupMember(groupId, data);
        return Response.ok(member.toJSON()).build();
    }

    @GET
    @Path("{groupId}/members/{memberId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGroupMember(
            @PathParam("groupId") String groupId,
            @PathParam("memberId") String memberId) throws Exception {
        logger.debug("TPSGroupResource.getGroupMember(): groupId={}, memberId={}", groupId, memberId);
        GroupMemberData member = createBase().getGroupMember(groupId, memberId);
        return Response.ok(member.toJSON()).build();
    }

    @DELETE
    @Path("{groupId}/members/{memberId}")
    public Response removeGroupMember(
            @PathParam("groupId") String groupId,
            @PathParam("memberId") String memberId) throws Exception {
        logger.debug("TPSGroupResource.removeGroupMember(): groupId={}, memberId={}", groupId, memberId);
        createBase().removeGroupMember(groupId, memberId);
        return Response.noContent().build();
    }
}

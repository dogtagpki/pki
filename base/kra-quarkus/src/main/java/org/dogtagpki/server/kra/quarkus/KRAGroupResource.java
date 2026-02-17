//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.net.URI;
import java.net.URLEncoder;
import java.util.Locale;

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

/**
 * JAX-RS resource for KRA group management.
 * Replaces KRAGroupServlet.
 */
@Path("v2/admin/groups")
public class KRAGroupResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAGroupResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

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
        logger.debug("KRAGroupResource.findGroups()");
        GroupCollection groups = createBase().findGroups(filter, start, size);
        return Response.ok(groups.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addGroup(String requestData) throws Exception {
        logger.debug("KRAGroupResource.addGroup()");
        GroupData groupData = JSONSerializer.fromJSON(requestData, GroupData.class);
        GroupData group = createBase().addGroup(groupData, Locale.getDefault());
        String encodedGroupID = URLEncoder.encode(group.getGroupID(), "UTF-8");
        URI location = uriInfo.getAbsolutePathBuilder().path(encodedGroupID).build();
        return Response.created(location).entity(group.toJSON()).build();
    }

    @GET
    @Path("{groupId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGroup(@PathParam("groupId") String groupId) throws Exception {
        logger.debug("KRAGroupResource.getGroup(): groupId={}", groupId);
        GroupData group = createBase().getGroup(groupId, Locale.getDefault());
        return Response.ok(group.toJSON()).build();
    }

    @PATCH
    @Path("{groupId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyGroup(@PathParam("groupId") String groupId, String requestData) throws Exception {
        logger.debug("KRAGroupResource.modifyGroup(): groupId={}", groupId);
        GroupData groupData = JSONSerializer.fromJSON(requestData, GroupData.class);
        GroupData group = createBase().modifyGroup(groupId, groupData, Locale.getDefault());
        return Response.ok(group.toJSON()).build();
    }

    @DELETE
    @Path("{groupId}")
    public Response removeGroup(@PathParam("groupId") String groupId) throws Exception {
        logger.debug("KRAGroupResource.removeGroup(): groupId={}", groupId);
        createBase().removeGroup(groupId, Locale.getDefault());
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
        logger.debug("KRAGroupResource.findGroupMembers(): groupId={}", groupId);
        GroupMemberCollection members = createBase().findGroupMembers(groupId, filter, start, size, Locale.getDefault());
        return Response.ok(members.toJSON()).build();
    }

    @POST
    @Path("{groupId}/members")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addGroupMember(@PathParam("groupId") String groupId, String requestData) throws Exception {
        logger.debug("KRAGroupResource.addGroupMember(): groupId={}", groupId);
        GroupMemberData memberData = JSONSerializer.fromJSON(requestData, GroupMemberData.class);
        GroupMemberData member = createBase().addGroupMember(groupId, memberData, Locale.getDefault());
        String encodedMemberID = URLEncoder.encode(member.getID(), "UTF-8");
        URI location = uriInfo.getAbsolutePathBuilder().path(encodedMemberID).build();
        return Response.created(location).entity(member.toJSON()).build();
    }

    @GET
    @Path("{groupId}/members/{memberId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGroupMember(@PathParam("groupId") String groupId, @PathParam("memberId") String memberId) throws Exception {
        logger.debug("KRAGroupResource.getGroupMember(): groupId={}, memberId={}", groupId, memberId);
        GroupMemberData member = createBase().getGroupMember(groupId, memberId, Locale.getDefault());
        return Response.ok(member.toJSON()).build();
    }

    @DELETE
    @Path("{groupId}/members/{memberId}")
    public Response removeGroupMember(@PathParam("groupId") String groupId, @PathParam("memberId") String memberId) throws Exception {
        logger.debug("KRAGroupResource.removeGroupMember(): groupId={}, memberId={}", groupId, memberId);
        createBase().removeGroupMember(groupId, memberId, Locale.getDefault());
        return Response.noContent().build();
    }
}

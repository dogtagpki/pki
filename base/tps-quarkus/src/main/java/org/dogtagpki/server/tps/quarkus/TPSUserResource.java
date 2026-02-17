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

import org.dogtagpki.server.rest.base.UserServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.user.UserCertCollection;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserCollection;
import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserMembershipCollection;
import com.netscape.certsrv.user.UserMembershipData;
import com.netscape.certsrv.util.JSONSerializer;

@Path("v2/admin/users")
public class TPSUserResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSUserResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Context
    UriInfo uriInfo;

    private UserServletBase createBase() {
        return new UserServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findUsers(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSUserResource.findUsers()");
        UserCollection users = createBase().findUsers(filter, start, size);
        return Response.ok(users.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addUser(String requestData) throws Exception {
        logger.debug("TPSUserResource.addUser()");
        UserData data = JSONSerializer.fromJSON(requestData, UserData.class);
        UserData user = createBase().addUser(data);
        String encodedID = URLEncoder.encode(user.getUserID(), "UTF-8");
        java.net.URI location = uriInfo.getAbsolutePathBuilder().path(encodedID).build();
        return Response.created(location).entity(user.toJSON()).build();
    }

    @GET
    @Path("{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@PathParam("userId") String userId) throws Exception {
        logger.debug("TPSUserResource.getUser(): userId={}", userId);
        UserData user = createBase().getUser(userId);
        return Response.ok(user.toJSON()).build();
    }

    @PATCH
    @Path("{userId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyUser(@PathParam("userId") String userId, String requestData) throws Exception {
        logger.debug("TPSUserResource.modifyUser(): userId={}", userId);
        UserData data = JSONSerializer.fromJSON(requestData, UserData.class);
        UserData user = createBase().modifyUser(userId, data);
        return Response.ok(user.toJSON()).build();
    }

    @DELETE
    @Path("{userId}")
    public Response removeUser(@PathParam("userId") String userId) throws Exception {
        logger.debug("TPSUserResource.removeUser(): userId={}", userId);
        createBase().removeUser(userId);
        return Response.noContent().build();
    }

    @GET
    @Path("{userId}/certs")
    @Produces(MediaType.APPLICATION_JSON)
    public Response findUserCerts(
            @PathParam("userId") String userId,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSUserResource.findUserCerts(): userId={}", userId);
        UserCertCollection certs = createBase().findUserCerts(userId, start, size);
        return Response.ok(certs.toJSON()).build();
    }

    @POST
    @Path("{userId}/certs")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addUserCert(@PathParam("userId") String userId, String requestData) throws Exception {
        logger.debug("TPSUserResource.addUserCert(): userId={}", userId);
        UserCertData data = JSONSerializer.fromJSON(requestData, UserCertData.class);
        UserCertData cert = createBase().addUserCert(userId, data);
        return Response.ok(cert.toJSON()).build();
    }

    @GET
    @Path("{userId}/certs/{certId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserCert(
            @PathParam("userId") String userId,
            @PathParam("certId") String certId) throws Exception {
        logger.debug("TPSUserResource.getUserCert(): userId={}, certId={}", userId, certId);
        UserCertData cert = createBase().getUserCert(userId, certId);
        return Response.ok(cert.toJSON()).build();
    }

    @DELETE
    @Path("{userId}/certs/{certId}")
    public Response removeUserCert(
            @PathParam("userId") String userId,
            @PathParam("certId") String certId) throws Exception {
        logger.debug("TPSUserResource.removeUserCert(): userId={}, certId={}", userId, certId);
        createBase().removeUserCert(userId, certId);
        return Response.noContent().build();
    }

    @GET
    @Path("{userId}/memberships")
    @Produces(MediaType.APPLICATION_JSON)
    public Response findUserMemberships(
            @PathParam("userId") String userId,
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSUserResource.findUserMemberships(): userId={}", userId);
        UserMembershipCollection memberships = createBase().findUserMemberships(userId, filter, start, size);
        return Response.ok(memberships.toJSON()).build();
    }

    @POST
    @Path("{userId}/memberships")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addUserMembership(@PathParam("userId") String userId, String requestData) throws Exception {
        logger.debug("TPSUserResource.addUserMembership(): userId={}", userId);
        UserMembershipData data = JSONSerializer.fromJSON(requestData, UserMembershipData.class);
        UserMembershipData membership = createBase().addUserMembership(userId, data);
        return Response.ok(membership.toJSON()).build();
    }

    @DELETE
    @Path("{userId}/memberships/{groupId}")
    public Response removeUserMembership(
            @PathParam("userId") String userId,
            @PathParam("groupId") String groupId) throws Exception {
        logger.debug("TPSUserResource.removeUserMembership(): userId={}, groupId={}", userId, groupId);
        createBase().removeUserMembership(userId, groupId);
        return Response.noContent().build();
    }
}

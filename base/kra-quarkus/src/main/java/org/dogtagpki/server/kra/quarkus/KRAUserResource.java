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

/**
 * JAX-RS resource for KRA user management.
 * Replaces KRAUserServlet.
 */
@Path("v2/admin/users")
public class KRAUserResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAUserResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

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
        logger.debug("KRAUserResource.findUsers()");
        UserCollection users = createBase().findUsers(filter, start, size, Locale.getDefault());
        return Response.ok(users.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addUser(String requestData) throws Exception {
        logger.debug("KRAUserResource.addUser()");
        UserData userData = JSONSerializer.fromJSON(requestData, UserData.class);
        UserData user = createBase().addUser(userData, Locale.getDefault());
        String encodedUserID = URLEncoder.encode(user.getUserID(), "UTF-8");
        URI location = uriInfo.getAbsolutePathBuilder().path(encodedUserID).build();
        return Response.created(location).entity(user.toJSON()).build();
    }

    @GET
    @Path("{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@PathParam("userId") String userId) throws Exception {
        logger.debug("KRAUserResource.getUser(): userId={}", userId);
        UserData user = createBase().getUser(userId, Locale.getDefault());
        return Response.ok(user.toJSON()).build();
    }

    @PATCH
    @Path("{userId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyUser(@PathParam("userId") String userId, String requestData) throws Exception {
        logger.debug("KRAUserResource.modifyUser(): userId={}", userId);
        UserData userData = JSONSerializer.fromJSON(requestData, UserData.class);
        UserData user = createBase().modifyUser(userId, userData, Locale.getDefault());
        return Response.ok(user.toJSON()).build();
    }

    @DELETE
    @Path("{userId}")
    public Response removeUser(@PathParam("userId") String userId) throws Exception {
        logger.debug("KRAUserResource.removeUser(): userId={}", userId);
        createBase().removeUser(userId, Locale.getDefault());
        return Response.noContent().build();
    }

    @GET
    @Path("{userId}/certs")
    @Produces(MediaType.APPLICATION_JSON)
    public Response findUserCerts(
            @PathParam("userId") String userId,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        logger.debug("KRAUserResource.findUserCerts(): userId={}", userId);
        UserCertCollection certs = createBase().findUserCerts(userId, start, size, Locale.getDefault());
        return Response.ok(certs.toJSON()).build();
    }

    @POST
    @Path("{userId}/certs")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addUserCert(@PathParam("userId") String userId, String requestData) throws Exception {
        logger.debug("KRAUserResource.addUserCert(): userId={}", userId);
        UserCertData certData = JSONSerializer.fromJSON(requestData, UserCertData.class);
        createBase().addUserCert(userId, certData, Locale.getDefault());
        return Response.created(uriInfo.getAbsolutePath()).build();
    }

    @GET
    @Path("{userId}/certs/{certId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserCert(@PathParam("userId") String userId, @PathParam("certId") String certId) throws Exception {
        logger.debug("KRAUserResource.getUserCert(): userId={}, certId={}", userId, certId);
        UserCertData cert = createBase().getUserCert(userId, certId, Locale.getDefault());
        return Response.ok(cert.toJSON()).build();
    }

    @DELETE
    @Path("{userId}/certs/{certId}")
    public Response removeUserCert(@PathParam("userId") String userId, @PathParam("certId") String certId) throws Exception {
        logger.debug("KRAUserResource.removeUserCert(): userId={}, certId={}", userId, certId);
        createBase().removeUserCert(userId, certId, Locale.getDefault());
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
        logger.debug("KRAUserResource.findUserMemberships(): userId={}", userId);
        UserMembershipCollection memberships = createBase().findUserMemberships(userId, filter, start, size, Locale.getDefault());
        return Response.ok(memberships.toJSON()).build();
    }

    @POST
    @Path("{userId}/memberships")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addUserMembership(@PathParam("userId") String userId, String groupId) throws Exception {
        logger.debug("KRAUserResource.addUserMembership(): userId={}, groupId={}", userId, groupId);
        UserMembershipData membership = createBase().addUserMembership(userId, groupId, Locale.getDefault());
        String encodedGroupID = URLEncoder.encode(groupId, "UTF-8");
        URI location = uriInfo.getAbsolutePathBuilder().path(encodedGroupID).build();
        return Response.created(location).entity(membership.toJSON()).build();
    }

    @DELETE
    @Path("{userId}/memberships/{groupId}")
    public Response removeUserMembership(@PathParam("userId") String userId, @PathParam("groupId") String groupId) throws Exception {
        logger.debug("KRAUserResource.removeUserMembership(): userId={}, groupId={}", userId, groupId);
        createBase().removeUserMembership(userId, groupId, Locale.getDefault());
        return Response.noContent().build();
    }
}

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
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.rest.base.UserBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.user.UserCollection;
import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserCertCollection;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserMembershipCollection;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * JAX-RS resource for CA user operations.
 * Replaces CAUserServlet.
 */
@Path("v2/admin/users")
public class CAUserResource {

    private static final Logger logger = LoggerFactory.getLogger(CAUserResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findUsers(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        UserBase userBase = new UserBase(engine);
        UserCollection users = userBase.findUsers(filter, start, size);
        return Response.ok(users.toJSON()).build();
    }

    @GET
    @Path("{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@PathParam("userId") String userId) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        UserBase userBase = new UserBase(engine);
        UserData user = userBase.getUser(userId);
        return Response.ok(user.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addUser(String requestData) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        UserBase userBase = new UserBase(engine);
        UserData userData = JSONSerializer.fromJSON(requestData, UserData.class);
        UserData newUser = userBase.addUser(userData);
        return Response.status(Response.Status.CREATED).entity(newUser.toJSON()).build();
    }

    @PATCH
    @Path("{userId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyUser(@PathParam("userId") String userId, String requestData) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        UserBase userBase = new UserBase(engine);
        UserData userData = JSONSerializer.fromJSON(requestData, UserData.class);
        UserData modifiedUser = userBase.modifyUser(userId, userData);
        return Response.ok(modifiedUser.toJSON()).build();
    }

    @DELETE
    @Path("{userId}")
    public Response removeUser(@PathParam("userId") String userId) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        UserBase userBase = new UserBase(engine);
        userBase.removeUser(userId);
        return Response.noContent().build();
    }

    @GET
    @Path("{userId}/certs")
    @Produces(MediaType.APPLICATION_JSON)
    public Response findUserCerts(
            @PathParam("userId") String userId,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        UserBase userBase = new UserBase(engine);
        UserCertCollection certs = userBase.findUserCerts(userId, start, size);
        return Response.ok(certs.toJSON()).build();
    }

    @POST
    @Path("{userId}/certs")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addUserCert(
            @PathParam("userId") String userId,
            String requestData) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        UserBase userBase = new UserBase(engine);
        UserCertData certData = JSONSerializer.fromJSON(requestData, UserCertData.class);
        userBase.addUserCert(userId, certData);
        return Response.status(Response.Status.CREATED).build();
    }

    @DELETE
    @Path("{userId}/certs/{certId}")
    public Response removeUserCert(
            @PathParam("userId") String userId,
            @PathParam("certId") String certId) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        UserBase userBase = new UserBase(engine);
        userBase.removeUserCert(userId, certId);
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
        CAEngine engine = engineQuarkus.getEngine();
        UserBase userBase = new UserBase(engine);
        UserMembershipCollection memberships = userBase.findUserMemberships(userId, filter, start, size);
        return Response.ok(memberships.toJSON()).build();
    }
}

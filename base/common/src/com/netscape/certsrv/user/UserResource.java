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

package com.netscape.certsrv.user;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
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
@Path("admin/users")
@ACLMapping("users")
@AuthMethodMapping("users")
public interface UserResource {

    public static final String ATTR_TPS_PROFILES = "tpsProfiles";
    public static final String ALL_PROFILES = "All Profiles";

    @GET
    @ClientResponseType(entityType=UserCollection.class)
    public Response findUsers(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @ClientResponseType(entityType=UserData.class)
    public Response addUser(UserData userData);

    @GET
    @Path("{userID}")
    @ClientResponseType(entityType=UserData.class)
    public Response getUser(@PathParam("userID") String userID);

    @PUT
    @Path("{userID}")
    @ClientResponseType(entityType=UserData.class)
    public Response replaceUser(@PathParam("userID") String userID, UserData userData);

    @PATCH
    @Path("{userID}")
    @ClientResponseType(entityType=UserData.class)
    public Response modifyUser(@PathParam("userID") String userID, UserData userData);

    @DELETE
    @Path("{userID}")
    @ClientResponseType(entityType=Void.class)
    public Response removeUser(@PathParam("userID") String userID);

    @GET
    @Path("{userID}/certs")
    @ClientResponseType(entityType=UserCertCollection.class)
    public Response findUserCerts(
            @PathParam("userID") String userID,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);


    @POST
    @Path("{userID}/certs")
    @ClientResponseType(entityType=UserCertData.class)
    public Response addUserCert(@PathParam("userID") String userID, UserCertData userCertData);

    @GET
    @Path("{userID}/certs/{certID}")
    @ClientResponseType(entityType=UserCertData.class)
    public Response getUserCert(@PathParam("userID") String userID, @PathParam("certID") String certID);

    @DELETE
    @Path("{userID}/certs/{certID}")
    @ClientResponseType(entityType=Void.class)
    public Response removeUserCert(@PathParam("userID") String userID, @PathParam("certID") String certID);

    @GET
    @Path("{userID}/memberships")
    @ClientResponseType(entityType=UserMembershipCollection.class)
    public Response findUserMemberships(
            @PathParam("userID") String userID,
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @Path("{userID}/memberships")
    @ClientResponseType(entityType=UserMembershipData.class)
    public Response addUserMembership(@PathParam("userID") String userID, String groupID);

    @DELETE
    @Path("{userID}/memberships/{groupID}")
    @ClientResponseType(entityType=Void.class)
    public Response removeUserMembership(@PathParam("userID") String userID, @PathParam("groupID") String groupID);
}

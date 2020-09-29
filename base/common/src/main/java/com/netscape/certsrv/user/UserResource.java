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
    public Response findUsers(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    public Response addUser(UserData userData);

    @GET
    @Path("{userID}")
    public Response getUser(@PathParam("userID") String userID);

    @PUT
    @Path("{userID}")
    public Response replaceUser(@PathParam("userID") String userID, UserData userData);

    @PATCH
    @Path("{userID}")
    public Response modifyUser(@PathParam("userID") String userID, UserData userData);

    @DELETE
    @Path("{userID}")
    public Response removeUser(@PathParam("userID") String userID);

    @GET
    @Path("{userID}/certs")
    public Response findUserCerts(
            @PathParam("userID") String userID,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);


    @POST
    @Path("{userID}/certs")
    public Response addUserCert(@PathParam("userID") String userID, UserCertData userCertData);

    @GET
    @Path("{userID}/certs/{certID}")
    public Response getUserCert(@PathParam("userID") String userID, @PathParam("certID") String certID);

    @DELETE
    @Path("{userID}/certs/{certID}")
    public Response removeUserCert(@PathParam("userID") String userID, @PathParam("certID") String certID);

    @GET
    @Path("{userID}/memberships")
    public Response findUserMemberships(
            @PathParam("userID") String userID,
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @Path("{userID}/memberships")
    public Response addUserMembership(@PathParam("userID") String userID, String groupID);

    @DELETE
    @Path("{userID}/memberships/{groupID}")
    public Response removeUserMembership(@PathParam("userID") String userID, @PathParam("groupID") String groupID);
}

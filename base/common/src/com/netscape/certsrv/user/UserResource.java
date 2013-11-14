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
@Path("admin/users")
@ACLMapping("users")
@AuthMethodMapping("users")
public interface UserResource {

    public static final String ATTR_TPS_PROFILES = "tpsProfiles";
    public static final String ALL_PROFILES = "All Profiles";

    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public UserCollection findUsers(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @ClientResponseType(entityType=UserData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response addUser(UserData userData);

    @GET
    @Path("{userID}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public UserData getUser(@PathParam("userID") String userID);

    @POST
    @Path("{userID}")
    @ClientResponseType(entityType=UserData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response modifyUser(@PathParam("userID") String userID, UserData userData);

    @DELETE
    @Path("{userID}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void removeUser(@PathParam("userID") String userID);

    @GET
    @Path("{userID}/certs")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public UserCertCollection findUserCerts(
            @PathParam("userID") String userID,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);


    @POST
    @Path("{userID}/certs")
    @ClientResponseType(entityType=UserCertData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response addUserCert(@PathParam("userID") String userID, UserCertData userCertData);

    @GET
    @Path("{userID}/certs/{certID}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public UserCertData getUserCert(@PathParam("userID") String userID, @PathParam("certID") String certID);

    @DELETE
    @Path("{userID}/certs/{certID}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void removeUserCert(@PathParam("userID") String userID, @PathParam("certID") String certID);

    @GET
    @Path("{userID}/memberships")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public UserMembershipCollection findUserMemberships(
            @PathParam("userID") String userID,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @Path("{userID}/memberships")
    @ClientResponseType(entityType=UserMembershipData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response addUserMembership(@PathParam("userID") String userID, String groupID);

    @DELETE
    @Path("{userID}/memberships/{groupID}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void removeUserMembership(@PathParam("userID") String userID, @PathParam("groupID") String groupID);
}

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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.tps.profile;

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
@Path("profiles")
@AuthMethodMapping("profiles")
@ACLMapping("profiles.read")
public interface ProfileResource {

    @GET
    @ClientResponseType(entityType=ProfileCollection.class)
    public Response findProfiles(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{profileID}")
    @ClientResponseType(entityType=ProfileData.class)
    public Response getProfile(@PathParam("profileID") String profileID);

    @POST
    @ACLMapping("profiles.add")
    @ClientResponseType(entityType=ProfileData.class)
    public Response addProfile(ProfileData profileData);

    @PATCH
    @Path("{profileID}")
    @ACLMapping("profiles.modify")
    @ClientResponseType(entityType=ProfileData.class)
    public Response updateProfile(
            @PathParam("profileID") String profileID,
            ProfileData profileData);

    @POST
    @Path("{profileID}")
    @ACLMapping("profiles.change-status")
    @ClientResponseType(entityType=ProfileData.class)
    public Response changeStatus(
            @PathParam("profileID") String profileID,
            @QueryParam("action") String action);

    @DELETE
    @Path("{profileID}")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("profiles.remove")
    public Response removeProfile(@PathParam("profileID") String profileID);
}

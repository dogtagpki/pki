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

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

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
    public Response findProfiles(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{profileID}")
    public Response getProfile(@PathParam("profileID") String profileID);

    @POST
    @ACLMapping("profiles.add")
    public Response addProfile(ProfileData profileData);

    @PATCH
    @Path("{profileID}")
    @ACLMapping("profiles.modify")
    public Response updateProfile(
            @PathParam("profileID") String profileID,
            ProfileData profileData);

    @POST
    @Path("{profileID}")
    @ACLMapping("profiles.change-status")
    public Response changeStatus(
            @PathParam("profileID") String profileID,
            @QueryParam("action") String action);

    @DELETE
    @Path("{profileID}")
    @ACLMapping("profiles.remove")
    public Response removeProfile(@PathParam("profileID") String profileID);
}

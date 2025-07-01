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
@Path("profile-mappings")
@AuthMethodMapping("profile-mappings")
@ACLMapping("profile-mappings.read")
public interface ProfileMappingResource {

    @GET
    public Response findProfileMappings(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{profileMappingID}")
    public Response getProfileMapping(@PathParam("profileMappingID") String profileMappingID);

    @POST
    @ACLMapping("profile-mappings.add")
    public Response addProfileMapping(ProfileMappingData profileMappingData);

    @PATCH
    @Path("{profileMappingID}")
    @ACLMapping("profile-mappings.modify")
    public Response updateProfileMapping(
            @PathParam("profileMappingID") String profileMappingID,
            ProfileMappingData profileMappingData);

    @POST
    @Path("{profileMappingID}")
    @ACLMapping("profiles-mappings.change-status")
    public Response changeStatus(
            @PathParam("profileMappingID") String profileMappingID,
            @QueryParam("action") String action);

    @DELETE
    @Path("{profileMappingID}")
    @ACLMapping("profile-mappings.remove")
    public Response removeProfileMapping(@PathParam("profileMappingID") String profileMappingID);
}

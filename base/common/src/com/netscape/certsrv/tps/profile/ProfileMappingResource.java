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

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
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
@Path("profile-mappings")
@AuthMethodMapping("profile-mappings")
@ACLMapping("profile-mappings.read")
public interface ProfileMappingResource {

    @GET
    @ClientResponseType(entityType=ProfileMappingCollection.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response findProfileMappings(
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("{profileMappingID}")
    @ClientResponseType(entityType=ProfileMappingData.class)
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response getProfileMapping(@PathParam("profileMappingID") String profileMappingID);

    @POST
    @ACLMapping("profile-mappings.add")
    @ClientResponseType(entityType=ProfileMappingData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response addProfileMapping(ProfileMappingData profileMappingData);

    @PUT
    @Path("{profileMappingID}")
    @ACLMapping("profile-mappings.modify")
    @ClientResponseType(entityType=ProfileMappingData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response updateProfileMapping(
            @PathParam("profileMappingID") String profileMappingID,
            ProfileMappingData profileMappingData);

    @POST
    @Path("{profileMappingID}")
    @ACLMapping("profiles-mappings.approve")
    @ClientResponseType(entityType=ProfileMappingData.class)
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response changeProfileMappingStatus(
            @PathParam("profileMappingID") String profileMappingID,
            @QueryParam("action") String action);

    @DELETE
    @Path("{profileMappingID}")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("profile-mappings.remove")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response removeProfileMapping(@PathParam("profileMappingID") String profileMappingID);
}

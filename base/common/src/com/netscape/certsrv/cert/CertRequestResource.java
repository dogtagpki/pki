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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.cert;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.request.RequestId;

@Path("")
public interface CertRequestResource {

    @POST
    @Path("certrequests")
    @ClientResponseType(entityType=CertRequestInfos.class)
    public Response enrollCert(CertEnrollmentRequest data);

    /**
     * Used to retrieve cert request info for a specific request
     */
    @GET
    @Path("certrequests/{id}")
    @ClientResponseType(entityType=CertRequestInfo.class)
    public Response getRequestInfo(@PathParam("id") RequestId id);

    /**
     * Used to generate list of cert requests based on the search parameters
     */
    @GET
    @Path("agent/certrequests")
    @ClientResponseType(entityType=CertRequestInfos.class)
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response listRequests(@QueryParam("requestState") String requestState,
            @QueryParam("requestType") String requestType,
            @QueryParam("start") RequestId start,
            @QueryParam("pageSize") Integer pageSize,
            @QueryParam("maxResults") Integer maxResults,
            @QueryParam("maxTime") Integer maxTime);

    @GET
    @Path("agent/certrequests/{id}")
    @ClientResponseType(entityType=CertReviewResponse.class)
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response reviewRequest(@PathParam("id") RequestId id);

    @GET
    @Path("certrequests/profiles")
    @ClientResponseType(entityType=ProfileDataInfos.class)
    public Response listEnrollmentTemplates(
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("certrequests/profiles/{id}")
    @ClientResponseType(entityType=CertEnrollmentRequest.class)
    public Response getEnrollmentTemplate(@PathParam("id") String id);

    @POST
    @Path("agent/certrequests/{id}/approve")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response approveRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/reject")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response rejectRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/cancel")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response cancelRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/update")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response updateRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/validate")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response validateRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/unassign")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response unassignRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/assign")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response assignRequest(@PathParam("id") RequestId id, CertReviewResponse data);
}

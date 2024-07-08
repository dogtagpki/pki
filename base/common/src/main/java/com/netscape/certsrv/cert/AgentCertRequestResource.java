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

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.request.RequestId;

@Path("agent/certrequests")
public interface AgentCertRequestResource {

    /**
     * Used to generate list of cert requests based on the search parameters
     */
    @GET
    @Path("")
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response listRequests(@QueryParam("requestState") String requestState,
            @QueryParam("requestType") String requestType,
            @QueryParam("start") RequestId start,
            @QueryParam("pageSize") Integer pageSize,
            @QueryParam("maxResults") Integer maxResults,
            @QueryParam("maxTime") Integer maxTime);

    @GET
    @Path("{id}")
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response reviewRequest(@PathParam("id") RequestId id);

    @POST
    @Path("{id}/approve")
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response approveRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("{id}/reject")
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response rejectRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("{id}/cancel")
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response cancelRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("{id}/update")
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response updateRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("{id}/validate")
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response validateRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("{id}/unassign")
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response unassignRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("{id}/assign")
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public Response assignRequest(@PathParam("id") RequestId id, CertReviewResponse data);
}

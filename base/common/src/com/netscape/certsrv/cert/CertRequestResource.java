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

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.request.RequestId;

@Path("")
public interface CertRequestResource {

    // Enrollment - used to test integration with a browser
    @POST
    @Path("certrequests")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED })
    public CertRequestInfos enrollCert(MultivaluedMap<String, String> form);

    @POST
    @Path("certrequests")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public CertRequestInfos enrollCert(CertEnrollmentRequest data);

    /**
     * Used to retrieve cert request info for a specific request
     */
    @GET
    @Path("certrequests/{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public CertRequestInfo getRequestInfo(@PathParam("id") RequestId id);

    /**
     * Used to generate list of cert requests based on the search parameters
     */
    @GET
    @Path("agent/certrequests")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public CertRequestInfos listRequests(@QueryParam("requestState") String requestState,
            @QueryParam("requestType") String requestType,
            @QueryParam("start") RequestId start,
            @QueryParam("pageSize") Integer pageSize,
            @QueryParam("maxResults") Integer maxResults,
            @QueryParam("maxTime") Integer maxTime);

    @GET
    @Path("agent/certrequests/{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public CertReviewResponse reviewRequest(@PathParam("id") RequestId id);

    @GET
    @Path("certrequests/profiles")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public ProfileDataInfos listEnrollmentTemplates(
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("certrequests/profiles/{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public CertEnrollmentRequest getEnrollmentTemplate(@PathParam("id") String id);

    @POST
    @Path("agent/certrequests/{id}/approve")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public void approveRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/reject")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public void rejectRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/cancel")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public void cancelRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/update")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public void updateRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/validate")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public void validateRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/unassign")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public void unassignRequest(@PathParam("id") RequestId id, CertReviewResponse data);

    @POST
    @Path("agent/certrequests/{id}/assign")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    @ACLMapping("certrequests")
    @AuthMethodMapping("certrequests")
    public void assignRequest(@PathParam("id") RequestId id, CertReviewResponse data);

}

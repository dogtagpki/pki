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
package com.netscape.cms.servlet.request;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.request.model.AgentEnrollmentRequestData;
import com.netscape.cms.servlet.request.model.CertRequestInfo;
import com.netscape.cms.servlet.request.model.CertRequestInfos;
import com.netscape.cms.servlet.request.model.EnrollmentRequestData;

@Path("/certrequest")
public interface CertRequestResource {

    /**
     * Used to retrieve cert request info for a specific request
     */
    @GET
    @Path("{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public CertRequestInfo getRequestInfo(@PathParam("id") RequestId id);

    @GET
    @Path("{id}/agentView")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public AgentEnrollmentRequestData reviewRequest(@PathParam("id") RequestId id);

    // Enrollment - used to test integration with a browser
    @POST
    @Path("enroll")
    @Produces({ MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED })
    public CertRequestInfos enrollCert(MultivaluedMap<String, String> form);

    @POST
    @Path("enroll")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public CertRequestInfos enrollCert(EnrollmentRequestData data);

    @POST
    @Path("{id}/approve")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void approveRequest(@PathParam("id") RequestId id, AgentEnrollmentRequestData data);

    @POST
    @Path("{id}/reject")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void rejectRequest(@PathParam("id") RequestId id, AgentEnrollmentRequestData data);

    @POST
    @Path("{id}/cancel")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void cancelRequest(@PathParam("id") RequestId id, AgentEnrollmentRequestData data);

    @POST
    @Path("{id}/update")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void updateRequest(@PathParam("id") RequestId id, AgentEnrollmentRequestData data);

    @POST
    @Path("{id}/validate")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void validateRequest(@PathParam("id") RequestId id, AgentEnrollmentRequestData data);

    @POST
    @Path("{id}/unassign")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void unassignRequest(@PathParam("id") RequestId id, AgentEnrollmentRequestData data);

    @POST
    @Path("{id}/assign")
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public void assignRequest(@PathParam("id") RequestId id, AgentEnrollmentRequestData data);
}

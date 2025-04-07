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

import com.netscape.certsrv.request.RequestId;

@Path("certrequests")
public interface CertRequestResource {

    @POST
    @Path("")
    public Response enrollCert(
        String enrollmentRequest,
        @QueryParam("issuer-id") String caIDString,
        @QueryParam("issuer-dn") String caDNString) throws Exception;

    /**
     * Used to retrieve cert request info for a specific request
     */
    @GET
    @Path("{id}")
    public Response getRequestInfo(@PathParam("id") RequestId id);

    @GET
    @Path("profiles")
    public Response listEnrollmentTemplates(
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @GET
    @Path("profiles/{id}")
    public Response getEnrollmentTemplate(@PathParam("id") String id);
}

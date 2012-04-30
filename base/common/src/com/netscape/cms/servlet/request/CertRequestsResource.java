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

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.request.model.CertRequestInfos;

@Path("/certrequests")
public interface CertRequestsResource {

    public static final int DEFAULT_START = 0;
    public static final int DEFAULT_PAGESIZE = 20;
    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;

    /**
     * Used to generate list of cert requests based on the search parameters
     */
    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public CertRequestInfos listRequests(@QueryParam("requestState") String requestState,
            @QueryParam("requestType") String requestType,
            @DefaultValue("" + DEFAULT_START) @QueryParam("start") RequestId start,
            @DefaultValue("" + DEFAULT_PAGESIZE) @QueryParam("pageSize") int pageSize,
            @DefaultValue("" + DEFAULT_MAXRESULTS) @QueryParam("maxResults") int maxResults,
            @DefaultValue("" + DEFAULT_MAXTIME) @QueryParam("maxTime") int maxTime);

}
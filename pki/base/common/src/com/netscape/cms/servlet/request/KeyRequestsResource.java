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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
 
package com.netscape.cms.servlet.request;

import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSResource;
import com.netscape.cms.servlet.request.model.KeyRequestDAO;
import com.netscape.cms.servlet.request.model.KeyRequestInfo;
 
/**
 * @author alee
 *
 */
@Path("/keyrequests")
public class KeyRequestsResource extends CMSResource {
 
    @Context
    UriInfo uriInfo;

    /**
     * Used to generate list of key requests based on the search parameters
     */
    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public List<KeyRequestInfo> listRequests() {
        // auth and authz
        // parse search parameters from uriInfo and create search filter
        // String clientID = uriInfo.getQueryParameters().getFirst(CLIENT_ID);
        String filter = "requestState=complete";
        KeyRequestDAO reqDAO = new KeyRequestDAO();
        List<KeyRequestInfo> requests;
        try {
            CMS.debug("alee: getting requests");
            requests = reqDAO.listRequests(filter, uriInfo);
            CMS.debug("alee: got request");
        } catch (EBaseException e) {
            // log error
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        CMS.debug("going into return");
        return requests;
    }
        
}

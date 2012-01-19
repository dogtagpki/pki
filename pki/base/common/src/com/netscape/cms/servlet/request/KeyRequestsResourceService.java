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

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.request.model.KeyRequestDAO;
import com.netscape.cms.servlet.request.model.KeyRequestInfos;
 
/**
 * @author alee
 *
 */
public class KeyRequestsResourceService extends CMSResourceService implements KeyRequestsResource{

    @Context
    UriInfo uriInfo;

    /**
     * Used to generate list of key requests based on the search parameters
     */
    public KeyRequestInfos listRequests(String requestState, String requestType, String clientID,
                                        String start_s, int pageSize, int maxResults,
                                        int maxTime) {
        // auth and authz
        
        // get ldap filter
        String filter = createSearchFilter(requestState, requestType, clientID);
        CMS.debug("listRequests: filter is " + filter);
       
        
        // get start marker
        int start = Integer.parseInt(KeyRequestsResource.DEFAULT_START);
        if (start_s != null) {
            try {
                if (start_s.trim().startsWith("0x")) {
                    start = Integer.parseInt(start_s.trim().substring(2), 16);
                } else {
                    start = Integer.parseInt(start_s.trim());
                }
            } catch (NumberFormatException e) {
                CMS.debug("listRequests: NumberformatException: Invalid value for start " + start_s);
                throw new WebApplicationException(Response.Status.NOT_FOUND);
            }
        }
        
        KeyRequestDAO reqDAO = new KeyRequestDAO();
        KeyRequestInfos requests;
        try {
            requests = reqDAO.listRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            CMS.debug("listRequests: error in obtaining request results" + e);
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        return requests;
    }

    private String createSearchFilter(String requestState, String requestType, String clientID) {
        String filter = "";
        int matches = 0;
        
        if ((requestState == null) && (requestType == null) && (clientID == null)) {
            filter = "(requeststate=*)";
            return filter;
        }
        
        if (requestState != null) {
            filter += "(requeststate=" + requestState + ")";
            matches ++;
        }
        
        if (requestType != null) {
            filter += "(requesttype=" + requestType + ")";
            matches ++;
        }
        
        if (clientID != null) {
            filter += "(clientID=" + clientID + ")";
            matches ++;
        }
        
        if (matches > 1) {
            filter = "(&" + filter + ")";
        }
        
        return filter;
    }
}

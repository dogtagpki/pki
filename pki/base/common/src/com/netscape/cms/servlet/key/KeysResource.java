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
/**
 * 
 */
package com.netscape.cms.servlet.key;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
 
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSResource;
import com.netscape.cms.servlet.key.model.KeyDAO;
import com.netscape.cms.servlet.key.model.KeyDataInfos;

/**
 * @author alee
 * 
 */
@Path("/keys")
public class KeysResource extends CMSResource {

    private static final String DEFAULT_MAXTIME = "10";
    private static final String DEFAULT_MAXRESULTS = "100";

    @Context
    UriInfo uriInfo;

    /**
     * Used to generate list of key infos based on the search parameters
     */
    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public KeyDataInfos listKeys(@QueryParam("clientID") String clientID,
                                 @QueryParam("status") String status,
                                 @DefaultValue(DEFAULT_MAXRESULTS) @QueryParam("maxResults") int maxResults,
                                 @DefaultValue(DEFAULT_MAXTIME) @QueryParam("maxTime") int maxTime) {
        // auth and authz
        
        // get ldap filter
        String filter = createSearchFilter(status, clientID);
        CMS.debug("listKeys: filter is " + filter);
       
        KeyDAO dao = new KeyDAO();
        KeyDataInfos infos;
        try {
            infos = dao.listKeys(filter, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        return infos;
    }
    
    private String createSearchFilter(String status, String clientID) {
        String filter = "";
        int matches = 0;
        
        if ((status == null) && (clientID == null)) {
            filter = "(serialno=*)";
            return filter;
        }
        
        if (status != null) {
            filter += "(status=" + status + ")";
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

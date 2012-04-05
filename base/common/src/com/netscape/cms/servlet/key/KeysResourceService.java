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

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.key.model.KeyDAO;
import com.netscape.cms.servlet.key.model.KeyDataInfos;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author alee
 *
 */
public class KeysResourceService extends CMSResourceService implements KeysResource {

    /**
     * Used to generate list of key infos based on the search parameters
     */
    public KeyDataInfos listKeys(String clientID, String status, int maxResults, int maxTime) {
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
            filter += "(status=" + LDAPUtil.escape(status) + ")";
            matches ++;
        }

        if (clientID != null) {
            filter += "(clientID=" + LDAPUtil.escape(clientID) + ")";
            matches ++;
        }

        if (matches > 1) {
            filter = "(&" + filter + ")";
        }

        return filter;
    }

}

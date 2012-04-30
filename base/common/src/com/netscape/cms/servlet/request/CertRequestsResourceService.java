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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.request.model.CertRequestDAO;
import com.netscape.cms.servlet.request.model.CertRequestInfos;
import com.netscape.cmsutil.ldap.LDAPUtil;
/**
 * @author alee
 *
 */
public class CertRequestsResourceService extends CMSResourceService implements CertRequestsResource {

    /**
     * Used to generate list of cert requests based on the search parameters
     */
    public CertRequestInfos listRequests(String requestState, String requestType,
            RequestId start, int pageSize, int maxResults, int maxTime) {
        // auth and authz

        // get ldap filter
        String filter = createSearchFilter(requestState, requestType);
        CMS.debug("listRequests: filter is " + filter);

        // get start marker
        if (start == null) {
            start = new RequestId(CertRequestsResource.DEFAULT_START);
        }

        CertRequestDAO reqDAO = new CertRequestDAO();
        CertRequestInfos requests;
        try {
            requests =  reqDAO.listRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            CMS.debug("listRequests: error in obtaining request results" + e);
            e.printStackTrace();
            throw new CMSException("Error listing cert requests!");
        }
        return requests;
    }

    private String createSearchFilter(String requestState, String requestType) {
        String filter = "";
        int matches = 0;

        if ((requestState == null) && (requestType == null)) {
            filter = "(requeststate=*)";
            return filter;
        }

        if (requestState != null) {
            filter += "(requeststate=" + LDAPUtil.escapeFilter(requestState) + ")";
            matches++;
        }

        if (requestType != null) {
            filter += "(requesttype=" + LDAPUtil.escapeFilter(requestType) + ")";
            matches++;
        }

        if (matches > 1) {
            filter = "(&" + filter + ")";
        }

        return filter;
    }
}

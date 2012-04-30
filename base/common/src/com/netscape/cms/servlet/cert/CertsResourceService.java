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
package com.netscape.cms.servlet.cert;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.cert.model.CertDAO;
import com.netscape.cms.servlet.cert.model.CertDataInfos;
import com.netscape.cms.servlet.cert.model.CertSearchData;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author alee
 *
 */
public class CertsResourceService extends CMSResourceService implements CertsResource {

    private String createSearchFilter(String status) {
        String filter = "";

        if ((status == null)) {
            filter = "(serialno=*)";
            return filter;
        }

        if (status != null) {
            filter += "(certStatus=" + LDAPUtil.escapeFilter(status) + ")";
        }

        return filter;
    }

    private String createSearchFilter(CertSearchData data) {

        if (data == null) {
            return null;
        }

        return data.buildFilter();

    }

    @Override
    public CertDataInfos listCerts(String status, int maxResults, int maxTime) {

        // get ldap filter
        String filter = createSearchFilter(status);
        CMS.debug("listKeys: filter is " + filter);

        CertDAO dao = new CertDAO();
        CertDataInfos infos;
        try {
            infos = dao.listCerts(filter, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new CMSException("Error listing certs in CertsResourceService.listCerts!");
        }
        return infos;
    }

    @Override
    public CertDataInfos searchCerts(CertSearchData data, int maxResults, int maxTime) {

        if (data == null) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
        String filter = createSearchFilter(data);
        CertDAO dao = new CertDAO();
        CertDataInfos infos;

        try {
            infos = dao.listCerts(filter, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new CMSException("Error listing certs in CertsResourceService.listCerts!");
        }

        return infos;
    }

}

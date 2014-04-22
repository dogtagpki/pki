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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca.rest;

import org.dogtagpki.server.rest.SystemConfigService;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.cms.servlet.csadmin.ConfigurationUtils;

/**
 * @author alee
 *
 */
public class CAInstallerService extends SystemConfigService {

    public CAInstallerService() throws EBaseException {
    }

    @Override
    public void finalizeConfiguration(ConfigurationRequest request) {

        super.finalizeConfiguration(request);

        try {
             if (!request.getIsClone().equals("true")) {
                 ConfigurationUtils.updateNextRanges();
             }

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in updating next serial number ranges in DB: " + e);
        }

        try {
            if (request.getIsClone().equals("true") && ConfigurationUtils.isSDHostDomainMaster(cs)) {
                // cloning a domain master CA, the clone is also master of its domain
                cs.putString("securitydomain.host", CMS.getEEHost());
                cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
                cs.putString("securitydomain.httpsadminport", CMS.getAdminPort());
                cs.putString("securitydomain.httpsagentport", CMS.getAgentPort());
                cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
                cs.putString("securitydomain.select", "new");
            }

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in determining if security domain host is a master CA");
        }
    }
}

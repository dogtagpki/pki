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
package org.dogtagpki.server.kra.rest;

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
public class KRAInstallerService extends SystemConfigService {

    public KRAInstallerService() throws EBaseException {
    }

    @Override
    public void finalizeConfiguration(ConfigurationRequest request) {

        super.finalizeConfiguration(request);

        try {
            String ca_host = cs.getString("preop.ca.hostname", "");

            // need to push connector information to the CA
            if (!request.getStandAlone() && !ca_host.equals("")) {
                ConfigurationUtils.updateConnectorInfo(CMS.getAgentHost(), CMS.getAgentPort());
                ConfigurationUtils.setupClientAuthUser();
            }

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in pushing KRA connector information to the CA: " + e);
        }

        try {
             if (!request.isClone()) {
                 ConfigurationUtils.updateNextRanges();
             }

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in updating next serial number ranges in DB: " + e);
        }
    }
}

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
package org.dogtagpki.server.ocsp.rest;

import org.dogtagpki.server.rest.SystemConfigService;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.cms.servlet.csadmin.ConfigurationUtils;

/**
 * @author alee
 *
 */
public class OCSPInstallerService extends SystemConfigService {

    private static final int DEF_REFRESH_IN_SECS_FOR_CLONE = 14400; // CRL Publishing schedule

    public OCSPInstallerService() throws EBaseException {
    }

    @Override
    public void finalizeConfiguration(ConfigurationRequest request) {

        super.finalizeConfiguration(request);

        try {
            String ca_host = cs.getString("preop.ca.hostname", "");

            // import the CA certificate into the OCSP
            // configure the CRL Publishing to OCSP in CA
            if (!ca_host.equals("")) {
                CMS.reinit(IOCSPAuthority.ID);
                if (!request.isClone())
                    ConfigurationUtils.importCACertToOCSP();
                else
                    CMS.debug("OCSPInstallerService: Skipping importCACertToOCSP for clone.");

                if (!request.getStandAlone()) {

                    // For now don't register publishing with the CA for a clone.
                    // Preserves existing functionality
                    // Next we need to treat the publishing of clones as a group ,
                    // and fail over amongst them.
                    if (!request.isClone())
                        ConfigurationUtils.updateOCSPConfig();

                    ConfigurationUtils.setupClientAuthUser();
                }
            }

            if (request.isClone()) {
                configureCloneRefresh(request);
            }

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in configuring CA publishing to OCSP: " + e);
        }
    }

    private void configureCloneRefresh(ConfigurationRequest request) {
        if (request == null || !request.isClone())
            return;

        //Set well know default value for OCSP clone
        cs.putInteger("ocsp.store.defStore.refreshInSec", DEF_REFRESH_IN_SECS_FOR_CLONE);

    }
}

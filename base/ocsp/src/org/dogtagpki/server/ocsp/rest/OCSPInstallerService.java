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

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.dogtagpki.server.rest.SystemConfigService;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.cms.servlet.csadmin.ConfigurationUtils;
import com.netscape.cmsutil.xml.XMLObject;

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
                        updateOCSPConfig();

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

    public void updateOCSPConfig() throws Exception {

        IConfigStore config = CMS.getConfigStore();

        String caHost = config.getString("preop.ca.hostname", "");
        int caPort = config.getInteger("preop.ca.httpsport", -1);

        CMS.debug("OCSPInstallerService: "
                + "Updating OCSP configuration in CA at https://" + caHost + ":" + caPort);

        String ocspHost = CMS.getAgentHost();
        int ocspPort = Integer.parseInt(CMS.getAgentPort());
        String sessionId = CMS.getConfigSDSessionId();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionId);
        content.putSingle("ocsp_host", ocspHost);
        content.putSingle("ocsp_port", ocspPort + "");

        String c = ConfigurationUtils.post(caHost, caPort, true, "/ca/ee/ca/updateOCSPConfig", content, null, null);
        if (c == null || c.equals("")) {
            CMS.debug("OCSPInstallerService: Unable to update OCSP configuration: No response from CA");
            throw new IOException("Unable to update OCSP configuration: No response from CA");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        CMS.debug("OCSPInstallerService: status: " + status);

        if (status.equals(ConfigurationUtils.SUCCESS)) {
            CMS.debug("OCSPInstallerService: Successfully updated OCSP configuration in CA");

        } else if (status.equals(ConfigurationUtils.AUTH_FAILURE)) {
            CMS.debug("OCSPInstallerService: Unable to update OCSP configuration: Authentication failure");
            throw new EAuthException(ConfigurationUtils.AUTH_FAILURE);

        } else {
            String error = parser.getValue("Error");
            CMS.debug("OCSPInstallerService: Unable to update OCSP configuration: " + error);
            throw new IOException(error);
        }
    }
}

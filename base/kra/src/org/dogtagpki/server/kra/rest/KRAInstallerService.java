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
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.cms.servlet.csadmin.ConfigurationUtils;
import com.netscape.cmsutil.xml.XMLObject;

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
                configureKRAConnector();
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

    public void configureKRAConnector() throws Exception {

        IConfigStore cs = CMS.getConfigStore();

        String url = cs.getString("preop.ca.url", "");
        if (url.equals("")) {
            CMS.debug("KRAInstallerService: preop.ca.url is not defined. External CA selected. No transport certificate setup is required");
            return;
        }

        String caHost = cs.getString("preop.ca.hostname", "");
        int caPort = cs.getInteger("preop.ca.httpsadminport", -1);

        CMS.debug("KRAInstallerService: "
                + "Configuring KRA connector in CA at https://" + caHost + ":" + caPort);

        String kraHost = CMS.getAgentHost();
        String kraPort = CMS.getAgentPort();
        String transportCert = cs.getString("kra.transport.cert", "");
        String sessionId = CMS.getConfigSDSessionId();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("ca.connector.KRA.enable", "true");
        content.putSingle("ca.connector.KRA.local", "false");
        content.putSingle("ca.connector.KRA.timeout", "30");
        content.putSingle("ca.connector.KRA.uri", "/kra/agent/kra/connector");
        content.putSingle("ca.connector.KRA.host", kraHost);
        content.putSingle("ca.connector.KRA.port", kraPort);
        content.putSingle("ca.connector.KRA.transportCert", transportCert);
        content.putSingle("sessionID", sessionId);

        String c = ConfigurationUtils.post(caHost, caPort, true, "/ca/admin/ca/updateConnector", content, null, null);
        if (c == null || c.equals("")) {
            CMS.debug("KRAInstallerService: Unable to configure KRA connector: No response from CA");
            throw new IOException("Unable to configure KRA connector: No response from CA");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        CMS.debug("KRAInstallerService: status: " + status);

        if (status.equals(ConfigurationUtils.SUCCESS)) {
            CMS.debug("KRAInstallerService: Successfully configured KRA connector in CA");

        } else if (status.equals(ConfigurationUtils.AUTH_FAILURE)) {
            CMS.debug("KRAInstallerService: Unable to configure KRA connector: Authentication failure");
            throw new EAuthException(ConfigurationUtils.AUTH_FAILURE);

        } else {
            String error = parser.getValue("Error");
            CMS.debug("KRAInstallerService: Unable to configure KRA connector: " + error);
            throw new IOException(error);
        }
    }
}

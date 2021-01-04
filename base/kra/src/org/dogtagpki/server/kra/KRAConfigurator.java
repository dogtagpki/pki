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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.kra;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmsutil.xml.XMLObject;

public class KRAConfigurator extends Configurator {

    public KRAConfigurator(CMSEngine engine) {
        super(engine);
    }

    @Override
    public void finalizeConfiguration(FinalizeConfigRequest request) throws Exception {

        try {
            PreOpConfig preopConfig = cs.getPreOpConfig();
            String ca_host = preopConfig.getString("ca.hostname", "");

            // need to push connector information to the CA
            if (!request.getStandAlone() && !ca_host.equals("")) {
                configureKRAConnector(request);
            }

        } catch (Exception e) {
            logger.error("Unable to configure KRA connector in CA: " + e.getMessage(), e);
            throw new PKIException("Unable to configure KRA connector in CA: " + e.getMessage(), e);
        }

        super.finalizeConfiguration(request);
    }

    public void configureKRAConnector(FinalizeConfigRequest request) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String url = preopConfig.getString("ca.url", "");
        if (url.equals("")) {
            logger.debug("KRAConfigurator: preop.ca.url is not defined. External CA selected. No transport certificate setup is required");
            return;
        }

        String caHost = preopConfig.getString("ca.hostname", "");
        int caPort = preopConfig.getInteger("ca.httpsadminport", -1);
        String serverURL = "https://" + caHost + ":" + caPort;

        logger.info("KRAConfigurator: Creating KRA connector in CA at " + serverURL);

        String kraHost = cs.getHostname();
        logger.info("KRAConfigurator: - host: " + kraHost);

        String kraPort = engine.getAgentPort();
        logger.info("KRAConfigurator: - port: " + kraPort);

        String path = "/kra/agent/kra/connector";
        logger.info("KRAConfigurator: - path: " + path);

        String transportCert = cs.getString("kra.transport.cert", "");
        String sessionId = request.getInstallToken().getToken();
        String transportCertNickname = cs.getString("kra.cert.transport.nickname");
        logger.info("KRAConfigurator: - transport nickname: " + transportCertNickname);

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("ca.connector.KRA.enable", "true");
        content.putSingle("ca.connector.KRA.local", "false");
        content.putSingle("ca.connector.KRA.timeout", "30");
        content.putSingle("ca.connector.KRA.uri", path);
        content.putSingle("ca.connector.KRA.host", kraHost);
        content.putSingle("ca.connector.KRA.port", kraPort);
        content.putSingle("ca.connector.KRA.transportCert", transportCert);
        content.putSingle("ca.connector.KRA.transportCertNickname",transportCertNickname);
        content.putSingle("sessionID", sessionId);

        logger.debug("KRAConfigurator: content: " + content);
        PKIClient client = createClient(serverURL, null, null);
        String response = client.post(
                "/ca/admin/ca/updateConnector",
                content,
                String.class);
        logger.debug("Response: " + response);

        if (response == null || response.equals("")) {
            logger.error("KRAConfigurator: Unable to configure KRA connector: No response from CA");
            throw new IOException("Unable to configure KRA connector: No response from CA");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.debug("KRAConfigurator: status: " + status);

        if (status.equals(Configurator.SUCCESS)) {
            logger.debug("KRAConfigurator: Successfully configured KRA connector in CA");

        } else if (status.equals(Configurator.AUTH_FAILURE)) {
            logger.error("KRAConfigurator: Unable to configure KRA connector: Authentication failure");
            throw new EAuthException(Configurator.AUTH_FAILURE);

        } else {
            String error = parser.getValue("Error");
            logger.error("KRAConfigurator: Unable to configure KRA connector: " + error);
            throw new IOException(error);
        }
    }
}

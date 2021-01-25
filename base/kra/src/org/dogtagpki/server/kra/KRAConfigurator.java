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

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.PreOpConfig;

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

        KRAConnectorInfo info = new KRAConnectorInfo();
        info.setEnable("true");
        info.setLocal("false");
        info.setTimeout("30");
        info.setUri(path);
        info.setHost(kraHost);
        info.setPort(kraPort);
        info.setTransportCert(transportCert);
        info.setTransportCertNickname(transportCertNickname);

        PKIClient client = createClient(serverURL, null, null);
        CAClient caClient = new CAClient(client);
        caClient.addKRAConnector(info, sessionId);
    }
}

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
package org.dogtagpki.server.tps;

import java.net.URI;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.kra.KRAClient;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.certsrv.tks.TKSClient;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class TPSConfigurator extends Configurator {

    public TPSConfigurator(CMSEngine engine) {
        super(engine);
    }

    @Override
    public void finalizeConfiguration(FinalizeConfigRequest request) throws Exception {

        URI secdomainURI = new URI(request.getSecurityDomainUri());
        URI caURI = request.getCaUri();
        URI tksURI = request.getTksUri();
        URI kraURI = request.getKraUri();
        String sessionID = request.getInstallToken().getToken();

        boolean keygen = request.getEnableServerSideKeyGen().equalsIgnoreCase("true");

        String csType = cs.getType();
        String uid = csType.toUpperCase() + "-" + cs.getHostname()
                + "-" + cs.getString("service.securePort", "");

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String subsystemName = preopConfig.getString("subsystem.name");

        String nickname = cs.getString("tps.subsystem.nickname");
        String tokenname = cs.getString("tps.subsystem.tokenname");

        if (!CryptoUtil.isInternalToken(tokenname)) {
            nickname = tokenname + ":" + nickname;
        }

        logger.debug("TPSConfigurator: subsystem cert: " + nickname);

        String subsystemCert = getSubsystemCert();

        try {
            logger.info("TPSConfigurator: Registering TPS to CA: " + caURI);
            PKIClient client = Configurator.createClient(caURI.toString(), null, null);
            CAClient caClient = new CAClient(client);
            caClient.addUser(secdomainURI, uid, subsystemName, subsystemCert, sessionID);

        } catch (Exception e) {
            String message = "Unable to register TPS to CA: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        try {
            logger.info("TPSConfigurator: Registering TPS to TKS: " + tksURI);
            PKIClient client = Configurator.createClient(tksURI.toString(), null, null);
            TKSClient tksClient = new TKSClient(client);
            tksClient.addUser(secdomainURI, uid, subsystemName, subsystemCert, sessionID);

        } catch (Exception e) {
            String message = "Unable to register TPS to TKS: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        if (keygen) {

            try {
                logger.info("TPSConfigurator: Registering TPS to KRA: " + kraURI);
                PKIClient client = Configurator.createClient(kraURI.toString(), null, null);
                KRAClient kraClient = new KRAClient(client);
                kraClient.addUser(secdomainURI, uid, subsystemName, subsystemCert, sessionID);

            } catch (Exception e) {
                String message = "Unable to register TPS to KRA: " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);
            }
        }

        super.finalizeConfiguration(request);
    }
}

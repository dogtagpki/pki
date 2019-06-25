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
import java.util.Collection;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.DatabaseSetupRequest;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.selftests.SelfTestSubsystem;
import com.netscape.cmsutil.xml.XMLObject;
import com.netscape.kra.KeyRecoveryAuthority;

public class KRAConfigurator extends Configurator {

    public KRAConfigurator(CMSEngine engine) {
        super(engine);
    }

    @Override
    public void initializeDatabase(DatabaseSetupRequest request) throws EBaseException {

        super.initializeDatabase(request);

        // Enable subsystems after database initialization.
        CMSEngine engine = CMS.getCMSEngine();

        engine.setSubsystemEnabled(KeyRecoveryAuthority.ID, true);
        engine.setSubsystemEnabled(SelfTestSubsystem.ID, true);
    }

    @Override
    public void getDatabaseGroups(Collection<String> groups) throws Exception {
        groups.add("Data Recovery Manager Agents");
        groups.add("Trusted Managers");
    }

    @Override
    public void finalizeConfiguration(FinalizeConfigRequest request) throws Exception {

        try {
            String ca_host = cs.getString("preop.ca.hostname", "");

            // need to push connector information to the CA
            if (!request.getStandAlone() && !ca_host.equals("")) {
                configureKRAConnector();
                setupClientAuthUser();
            }

        } catch (Exception e) {
            logger.error("Unable to configure KRA connector in CA: " + e.getMessage(), e);
            throw new PKIException("Unable to configure KRA connector in CA: " + e.getMessage(), e);
        }

        try {
             if (!request.isClone()) {
                 updateNextRanges();
             }

        } catch (Exception e) {
            logger.error("Unable to update next serial number ranges: " + e.getMessage(), e);
            throw new PKIException("Unable to update next serial number ranges: " + e.getMessage(), e);
        }

        super.finalizeConfiguration(request);
    }

    public void configureKRAConnector() throws Exception {

        CMSEngine engine = CMS.getCMSEngine();

        String url = cs.getString("preop.ca.url", "");
        if (url.equals("")) {
            logger.debug("KRAConfigurator: preop.ca.url is not defined. External CA selected. No transport certificate setup is required");
            return;
        }

        String caHost = cs.getString("preop.ca.hostname", "");
        int caPort = cs.getInteger("preop.ca.httpsadminport", -1);

        logger.debug("KRAConfigurator: "
                + "Configuring KRA connector in CA at https://" + caHost + ":" + caPort);

        String kraHost = engine.getAgentHost();
        String kraPort = engine.getAgentPort();
        String transportCert = cs.getString("kra.transport.cert", "");
        String sessionId = engine.getConfigSDSessionId();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("ca.connector.KRA.enable", "true");
        content.putSingle("ca.connector.KRA.local", "false");
        content.putSingle("ca.connector.KRA.timeout", "30");
        content.putSingle("ca.connector.KRA.uri", "/kra/agent/kra/connector");
        content.putSingle("ca.connector.KRA.host", kraHost);
        content.putSingle("ca.connector.KRA.port", kraPort);
        content.putSingle("ca.connector.KRA.transportCert", transportCert);
        content.putSingle("sessionID", sessionId);

        String c = Configurator.post(caHost, caPort, true, "/ca/admin/ca/updateConnector", content, null, null);
        if (c == null || c.equals("")) {
            logger.error("KRAConfigurator: Unable to configure KRA connector: No response from CA");
            throw new IOException("Unable to configure KRA connector: No response from CA");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
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

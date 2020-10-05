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
package org.dogtagpki.server.tps.installer;

import java.net.URI;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.ConnectorDatabase;
import org.dogtagpki.server.tps.config.ConnectorRecord;

import com.netscape.certsrv.base.PKIException;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;

/**
 * Utility class for TPS installation to be used both by the RESTful installer
 * and the UI Panels.
 *
 * @author alee
 *
 */

public class TPSInstaller {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSEngine.class);

    public TPSInstaller() {
    }

    public void configureCAConnector(URI uri, String nickname) throws Exception {
        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        ConnectorDatabase database = subsystem.getConnectorDatabase();
        database.addCAConnector(uri.getHost(), uri.getPort(), nickname);
    }

    public void configureTKSConnector(URI uri, String nickname) {

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        ConnectorDatabase database = subsystem.getConnectorDatabase();
        EngineConfig cs = engine.getConfig();
        PreOpConfig preopConfig = cs.getPreOpConfig();

        // TODO: see if this is only needed by wizard-based installation
        preopConfig.putString("tksinfo.select", uri.toString());

        try {
            database.addTKSConnector(uri.getHost(), uri.getPort(), nickname, false);

        } catch (Exception e) {
            logger.error("Unable to create TKS connector: " + e.getMessage(), e);
            throw new PKIException("Unable to create TKS connector: " + e.getMessage(), e);
        }
    }

    public void configureKRAConnector(Boolean keygen, URI uri, String nickname) {

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        ConnectorDatabase database = subsystem.getConnectorDatabase();
        EngineConfig cs = engine.getConfig();
        PreOpConfig preopConfig = cs.getPreOpConfig();

        if (keygen) {
            // TODO: see if this is only needed by wizard-based installation
            preopConfig.putString("krainfo.select", uri.toString());

            // TODO: see if there are other profiles need to be configured
            cs.putString("op.enroll.userKey.keyGen.encryption.serverKeygen.enable", "true");
            cs.putString("op.enroll.userKeyTemporary.keyGen.encryption.serverKeygen.enable", "true");
            cs.putString("op.enroll.soKey.keyGen.encryption.serverKeygen.enable", "true");
            cs.putString("op.enroll.soKeyTemporary.keyGen.encryption.serverKeygen.enable", "true");

            try {
                database.addKRAConnector(uri.getHost(), uri.getPort(), nickname);

            } catch (Exception e) {
                logger.error("Unable to create KRA connector: " + e.getMessage(), e);
                throw new PKIException("Unable to create KRA connector: " + e.getMessage(), e);
            }

        } else { // no keygen
            // TODO: see if there are other profiles need to be configured
            cs.putString("op.enroll.userKey.keyGen.encryption.serverKeygen.enable", "false");
            cs.putString("op.enroll.userKeyTemporary.keyGen.encryption.serverKeygen.enable", "false");
            cs.putString("op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme", "GenerateNewKey");
            cs.putString("op.enroll.userKeyTemporary.keyGen.encryption.recovery.onHold.scheme", "GenerateNewKey");
            cs.putString("op.enroll.soKey.keyGen.encryption.serverKeygen.enable", "false");
            cs.putString("op.enroll.soKeyTemporary.keyGen.encryption.serverKeygen.enable", "false");
            cs.putString("op.enroll.soKey.keyGen.encryption.recovery.destroyed.scheme", "GenerateNewKey");
            cs.putString("op.enroll.soKeyTemporary.keyGen.encryption.recovery.onHold.scheme", "GenerateNewKey");
        }

        try {
            String id = "tks1"; // there is only one default TKS connector

            // update keygen in TKS connector
            ConnectorRecord record = database.getRecord(id);
            record.setProperty(database.prefix + "." + id + ".serverKeygen", keygen.toString());
            database.updateRecord(id, record);

        } catch (Exception e) {
            logger.error("Unable to update TKS connector: " + e.getMessage(), e);
            throw new PKIException("Unable to update TKS connector", e);
        }
    }
}

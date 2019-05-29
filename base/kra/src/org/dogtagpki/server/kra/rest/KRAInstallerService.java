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

import org.dogtagpki.server.kra.KRAConfigurator;
import org.dogtagpki.server.rest.SystemConfigService;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.selftests.SelfTestSubsystem;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * @author alee
 *
 */
public class KRAInstallerService extends SystemConfigService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAInstallerService.class);

    public KRAConfigurator kraConfigurator;

    public KRAInstallerService() throws Exception {
        kraConfigurator = (KRAConfigurator) configurator;
    }

    public Configurator createConfigurator() {
        return new KRAConfigurator();
    }

    @Override
    public void initializeDatabase(ConfigurationRequest data) throws EBaseException {

        super.initializeDatabase(data);

        // Enable subsystems after database initialization.
        CMSEngine engine = CMS.getCMSEngine();

        engine.setSubsystemEnabled(KeyRecoveryAuthority.ID, true);
        engine.setSubsystemEnabled(SelfTestSubsystem.ID, true);
    }

    @Override
    public void finalizeConfiguration(ConfigurationRequest request) throws Exception {

        try {
            String ca_host = cs.getString("preop.ca.hostname", "");

            // need to push connector information to the CA
            if (!request.getStandAlone() && !ca_host.equals("")) {
                kraConfigurator.configureKRAConnector();
                configurator.setupClientAuthUser();
            }

        } catch (Exception e) {
            logger.error("KRAInstallerService: " + e.getMessage(), e);
            throw new PKIException("Errors in pushing KRA connector information to the CA: " + e);
        }

        try {
             if (!request.isClone()) {
                 configurator.updateNextRanges();
             }

        } catch (Exception e) {
            logger.error("KRAInstallerService: " + e.getMessage(), e);
            throw new PKIException("Errors in updating next serial number ranges in DB: " + e);
        }

        super.finalizeConfiguration(request);
    }
}

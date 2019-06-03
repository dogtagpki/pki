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
package org.dogtagpki.server.ca.rest;

import org.dogtagpki.server.ca.CAConfigurator;
import org.dogtagpki.server.rest.SystemConfigService;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.cert.CrossCertPairSubsystem;
import com.netscape.cmscore.profile.LDAPProfileSubsystem;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

/**
 * @author alee
 *
 */
public class CAInstallerService extends SystemConfigService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAInstallerService.class);

    public CAConfigurator caConfigurator;

    public CAInstallerService() throws Exception {
        caConfigurator = (CAConfigurator) configurator;
    }

    @Override
    public void initializeDatabase(ConfigurationRequest data) throws EBaseException {

        super.initializeDatabase(data);

        CMSEngine engine = CMS.getCMSEngine();

        if (!data.isClone()
                && engine.getSubsystem(IProfileSubsystem.ID) instanceof LDAPProfileSubsystem) {
            try {
                caConfigurator.importProfiles("/usr/share/pki");
            } catch (Exception e) {
                logger.error("Unable to import profiles: " + e.getMessage(), e);
                throw new PKIException("Unable to import profiles: " + e.getMessage(), e);
            }
        }
    }

    public void reinitSubsystems() throws EBaseException {

        super.reinitSubsystems();

        // Enable subsystems after database initialization.
        CMSEngine engine = CMS.getCMSEngine();

        engine.setSubsystemEnabled(CertificateAuthority.ID, true);
        engine.setSubsystemEnabled(CrossCertPairSubsystem.ID, true);
        engine.setSubsystemEnabled(SelfTestSubsystem.ID, true);

        engine.reinit(CertificateAuthority.ID);
    }
}

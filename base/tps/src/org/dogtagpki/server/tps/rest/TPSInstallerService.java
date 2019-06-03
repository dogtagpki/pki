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
package org.dogtagpki.server.tps.rest;

import org.dogtagpki.server.rest.SystemConfigService;
import org.dogtagpki.server.tps.installer.TPSInstaller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.AdminSetupResponse;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.selftests.SelfTestSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author alee
 *
 */
public class TPSInstallerService extends SystemConfigService  {

    public final static Logger logger = LoggerFactory.getLogger(TPSInstallerService.class);

    public TPSInstallerService() throws Exception {
    }

    @Override
    public void initializeDatabase(ConfigurationRequest data) throws EBaseException {

        super.initializeDatabase(data);

        // Enable subsystems after database initialization.
        CMSEngine engine = CMS.getCMSEngine();

        engine.setSubsystemEnabled(SelfTestSubsystem.ID, true);
    }

    @Override
    public AdminSetupResponse setupAdmin(AdminSetupRequest request) throws Exception {
        AdminSetupResponse response = super.setupAdmin(request);
        configurator.addProfilesToTPSUser(request.getAdminUID());
        return response;
    }

    @Override
    public void configureSubsystem(ConfigurationRequest request,
            String token, String domainXML) throws Exception {

        super.configureSubsystem(request, token, domainXML);

        SystemCertData subsystemCert = request.getSystemCert("subsystem");

        String nickname;
        if (CryptoUtil.isInternalToken(subsystemCert.getToken())) {
            nickname = subsystemCert.getNickname();
        } else {
            nickname = subsystemCert.getToken() + ":" + subsystemCert.getNickname();
        }

        // CA Info Panel
        configureCAConnector(request, nickname);

        // TKS Info Panel
        configureTKSConnector(request, nickname);

        //DRM Info Panel
        configureKRAConnector(request, nickname);

        //AuthDBPanel
        configurator.updateAuthdbInfo(request.getAuthdbBaseDN(),
                request.getAuthdbHost(), request.getAuthdbPort(),
                request.getAuthdbSecureConn());
    }

    public void configureCAConnector(ConfigurationRequest request, String nickname) {
        // TODO: get installer from session
        TPSInstaller installer = new TPSInstaller();
        installer.configureCAConnector(request.getCaUri(), nickname);
    }

    public void configureTKSConnector(ConfigurationRequest request, String nickname) {

        // TODO: get installer from session
        TPSInstaller installer = new TPSInstaller();
        installer.configureTKSConnector(request.getTksUri(), nickname);
    }

    public void configureKRAConnector(ConfigurationRequest request, String nickname) {

        boolean keygen = request.getEnableServerSideKeyGen().equalsIgnoreCase("true");

        // TODO: get installer from session
        TPSInstaller installer = new TPSInstaller();
        installer.configureKRAConnector(keygen, request.getKraUri(), nickname);
    }

    @Override
    public void configureDatabase(ConfigurationRequest request) throws EBaseException {

        super.configureDatabase(request);

        String dsHost = cs.getString("internaldb.ldapconn.host");
        String dsPort = cs.getString("internaldb.ldapconn.port");
        String baseDN = cs.getString("internaldb.basedn");

        cs.putString("tokendb.activityBaseDN", "ou=Activities," + baseDN);
        cs.putString("tokendb.baseDN", "ou=Tokens," + baseDN);
        cs.putString("tokendb.certBaseDN", "ou=Certificates," + baseDN);
        cs.putString("tokendb.userBaseDN", baseDN);
        cs.putString("tokendb.hostport", dsHost + ":" + dsPort);
    }
}

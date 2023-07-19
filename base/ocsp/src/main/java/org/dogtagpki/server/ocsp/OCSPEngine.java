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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ocsp;

import com.netscape.certsrv.base.Subsystem;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.ocsp.OCSPAuthority;

public class OCSPEngine extends CMSEngine {

    static OCSPEngine instance;

    public OCSPEngine() {
        super("OCSP");
        instance = this;
    }

    public static OCSPEngine getInstance() {
        return instance;
    }

    @Override
    public OCSPEngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new OCSPEngineConfig(storage);
    }

    @Override
    public OCSPEngineConfig getConfig() {
        return (OCSPEngineConfig) mConfig;
    }

    public OCSPAuthority getOCSP() {
        return (OCSPAuthority) getSubsystem(OCSPAuthority.ID);
    }

    @Override
    public void initSubsystem(Subsystem subsystem, ConfigStore subsystemConfig) throws Exception {

        if (subsystem instanceof OCSPAuthority) {
            // skip initialization during installation
            if (isPreOpMode()) return;
        }

        super.initSubsystem(subsystem, subsystemConfig);
        if (subsystem instanceof OCSPAuthority) {
            subsystem.startup();
        }
    }

    protected void startupSubsystems() throws Exception {

        for (Subsystem subsystem : subsystems.values()) {
            logger.info("CMSEngine: Starting " + subsystem.getId() + " subsystem");
            if (!(subsystem instanceof OCSPAuthority))
                subsystem.startup();
        }

        // global admin servlet. (anywhere else more fit for this ?)
    }
    @Override
    protected void initSequence() throws Exception {


        initDebug();
        init();
        initPasswordStore();
        initSubsystemListeners();
        initSecurityProvider();
        initPluginRegistry();
        initAuditor();
        initLogSubsystem();

        initClientSocketListener();
        initServerSocketListener();

        testLDAPConnections();
        initDatabase();

        initJssSubsystem();
        initDBSubsystem();
        initUGSubsystem();
        initOIDLoaderSubsystem();
        initX500NameSubsystem();
        // skip TP subsystem;
        // problem in needing dbsubsystem in constructor. and it's not used.
        initRequestSubsystem();


        startupSubsystems();

        initAuthSubsystem();
        initAuthzSubsystem();
        initCMSGateway();
        initJobsScheduler();

        configureAutoShutdown();
        configureServerCertNickname();

        initSecurityDomain();
    }


}

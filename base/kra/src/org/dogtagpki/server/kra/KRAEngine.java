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

package org.dogtagpki.server.kra;

import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.kra.KeyRecoveryAuthority;

@WebListener
public class KRAEngine extends CMSEngine implements ServletContextListener {

    public KRAEngine() throws Exception {
        super("KRA");
    }

    public static KRAEngine getInstance() {
        return (KRAEngine) CMS.getCMSEngine();
    }

    public EngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new KRAEngineConfig(storage);
    }

    public KRAEngineConfig getConfig() {
        return (KRAEngineConfig) mConfig;
    }

    public KRAConfigurator createConfigurator() throws Exception {
        return new KRAConfigurator(this);
    }

    public void initSubsystem(ISubsystem subsystem, IConfigStore subsystemConfig) throws Exception {

        if (subsystem instanceof KeyRecoveryAuthority) {
            // skip initialization during installation
            if (isPreOpMode()) return;
        }

        super.initSubsystem(subsystem, subsystemConfig);
    }

    public void startupSubsystems() throws Exception {

        super.startupSubsystems();

        IKeyRecoveryAuthority kra = (IKeyRecoveryAuthority) getSubsystem(IKeyRecoveryAuthority.ID);
        if (!isPreOpMode()) {
            logger.debug("KRAEngine: checking request serial number ranges for the KRA");
            kra.getRequestQueue().getRequestRepository().checkRanges();

            logger.debug("KRAEngine: checking key serial number ranges");
            kra.getKeyRepository().checkRanges();
        }
    }
}

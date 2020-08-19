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

package org.dogtagpki.server.tks;

import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.selftests.SelfTestSubsystem;
import com.netscape.tks.TKSAuthority;

@WebListener
public class TKSEngine extends CMSEngine implements ServletContextListener {

    public TKSEngine() throws Exception {
        super("TKS");
    }

    public static TKSEngine getInstance() {
        return (TKSEngine) CMS.getCMSEngine();
    }

    public EngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new TKSEngineConfig(storage);
    }

    public TKSEngineConfig getConfig() {
        return (TKSEngineConfig) mConfig;
    }

    public TKSConfigurator createConfigurator() throws Exception {
        return new TKSConfigurator(this);
    }

    protected void loadSubsystems() throws EBaseException {

        super.loadSubsystems();

        if (isPreOpMode()) {
            // Disable some subsystems before database initialization
            // in pre-op mode to prevent misleading exceptions.

            setSubsystemEnabled(TKSAuthority.ID, false);
            setSubsystemEnabled(SelfTestSubsystem.ID, false);
        }
    }
}

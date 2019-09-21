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

package org.dogtagpki.server.tps;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

public class TPSEngine extends CMSEngine {

    public TPSEngine() throws Exception {
        super("TPS");
    }

    public EngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new TPSEngineConfig(storage);
    }

    public TPSEngineConfig getConfig() {
        return (TPSEngineConfig) mConfig;
    }

    public TPSConfigurator createConfigurator() throws Exception {
        return new TPSConfigurator(this);
    }

    protected void loadSubsystems() throws EBaseException {

        super.loadSubsystems();

        if (isPreOpMode()) {
            // Disable some subsystems before database initialization
            // in pre-op mode to prevent misleading exceptions.

            setSubsystemEnabled(SelfTestSubsystem.ID, false);
        }
    }
}

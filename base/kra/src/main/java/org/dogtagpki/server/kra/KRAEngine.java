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

import javax.servlet.annotation.WebListener;

import com.netscape.certsrv.base.ISubsystem;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.KeyRequestRepository;
import com.netscape.kra.KeyRecoveryAuthority;

@WebListener
public class KRAEngine extends CMSEngine {

    public KRAEngine() throws Exception {
        super("KRA");
    }

    public static KRAEngine getInstance() {
        return (KRAEngine) CMS.getCMSEngine();
    }

    @Override
    public EngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new KRAEngineConfig(storage);
    }

    @Override
    public KRAEngineConfig getConfig() {
        return (KRAEngineConfig) mConfig;
    }

    public KeyRequestRepository getKeyRequestRepository() {
        return (KeyRequestRepository) requestRepository;
    }

    @Override
    public void initSubsystem(ISubsystem subsystem, ConfigStore subsystemConfig) throws Exception {

        if (subsystem instanceof KeyRecoveryAuthority) {
            // skip initialization during installation
            if (isPreOpMode()) return;
        }

        super.initSubsystem(subsystem, subsystemConfig);
    }

    @Override
    public void startupSubsystems() throws Exception {

        super.startupSubsystems();

        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) getSubsystem(KeyRecoveryAuthority.ID);
        if (!isPreOpMode()) {
            logger.debug("KRAEngine: checking request serial number ranges for the KRA");
            requestRepository.checkRanges();

            logger.debug("KRAEngine: checking key serial number ranges");
            kra.getKeyRepository().checkRanges();
        }
    }
}

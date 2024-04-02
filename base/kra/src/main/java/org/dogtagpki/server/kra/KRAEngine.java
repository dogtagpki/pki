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

import java.security.SecureRandom;

import com.netscape.certsrv.base.Subsystem;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmscore.dbs.ReplicaIDRepository;
import com.netscape.cmscore.request.KeyRequestRepository;
import com.netscape.kra.KeyRecoveryAuthority;

public class KRAEngine extends CMSEngine {

    static KRAEngine instance;

    protected KeyRepository keyRepository;
    protected ReplicaIDRepository replicaIDRepository;

    public KRAEngine() {
        super("KRA");
        instance = this;
    }

    public static KRAEngine getInstance() {
        return instance;
    }

    @Override
    public KRAEngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new KRAEngineConfig(storage);
    }

    @Override
    public KRAEngineConfig getConfig() {
        return (KRAEngineConfig) mConfig;
    }

    public KeyRecoveryAuthority getKRA() {
        return (KeyRecoveryAuthority) getSubsystem(KeyRecoveryAuthority.ID);
    }

    public KeyRequestRepository getKeyRequestRepository() {
        return (KeyRequestRepository) requestRepository;
    }

    public KeyRepository getKeyRepository() {
        return keyRepository;
    }

    public ReplicaIDRepository getReplicaIDRepository() {
        return replicaIDRepository;
    }

    public void initKeyRepository() throws Exception {

        logger.info("KRAEngine: Initializing key repository");

        KRAConfig kraConfig = getConfig().getKRAConfig();
        int increment = kraConfig.getInteger(KeyRecoveryAuthority.PROP_KEYDB_INC, 5);
        logger.info("KRAEngine: - increment: " + increment);

        SecureRandom secureRandom = jssSubsystem.getRandomNumberGenerator();

        keyRepository = new KeyRepository(secureRandom, dbSubsystem);
        keyRepository.setCMSEngine(this);
        keyRepository.init();
    }

    public void initReplicaIDRepository() throws Exception {

        logger.info("KRAEngine: Initializing replica ID repository");

        replicaIDRepository = new ReplicaIDRepository(dbSubsystem);
        replicaIDRepository.setCMSEngine(this);
        replicaIDRepository.init();
    }

    @Override
    public void init() throws Exception {
        initKeyRepository();
        initReplicaIDRepository();
        super.init();
    }

    @Override
    public void initSubsystem(Subsystem subsystem, ConfigStore subsystemConfig) throws Exception {

        if (subsystem instanceof KeyRecoveryAuthority) {
            // skip initialization during installation
            if (isPreOpMode()) return;
        }

        super.initSubsystem(subsystem, subsystemConfig);
    }

    @Override
    public void startupSubsystems() throws Exception {

        super.startupSubsystems();

        if (!isPreOpMode()) {
            logger.debug("KRAEngine: checking request serial number ranges for the KRA");
            requestRepository.checkRanges();

            logger.debug("KRAEngine: checking key serial number ranges");
            keyRepository.checkRanges();
        }
    }

    @Override
    protected void shutdownSubsystems() {

        super.shutdownSubsystems();

        if (keyRepository != null) {
            keyRepository.shutdown();
        }
    }
}

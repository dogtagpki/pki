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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.tks;

import org.dogtagpki.server.tks.TKSConfig;
import org.dogtagpki.server.tks.TKSEngine;
import org.dogtagpki.server.tks.TKSEngineConfig;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.cmscore.base.ConfigStore;

public class TKSAuthority extends Subsystem implements IAuthority {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TKSAuthority.class);

    public static final String ID = "tks";

    private String mNickname = null;
    private TKSConfig mConfig;
    protected String mId = null;
    public static final String PROP_NICKNAME = "nickName";

    /**
     * log interface
     */
    public void log(int level, String msg) {
    }

    /**
     * nickname of signing (id) cert
     */
    public void setNickname(String nickname) {
        mNickname = nickname;
    }

    @Override
    public String getNickname() {
        logger.debug("Error: TKSAuthority::getNickname - nickname of signing (id) cert");
        return mNickname;
    }

    @Override
    public String getOfficialName() {
        return "tks";
    }

    /**
     * Initializes this subsystem.
     * <P>
     * @param config configuration of this subsystem
     *
     * @exception EBaseException failed to initialize this RA
     */
    @Override
    public void init(ConfigStore config) throws EBaseException {

        TKSEngine engine = TKSEngine.getInstance();
        TKSEngineConfig engineConfig = engine.getConfig();

        mConfig = engineConfig.getTKSConfig();

        //mNickname = mConfig.getString(PROP_NICKNAME);
        logger.debug("TKS Authority (" + getId() + "): " + "Initialized Request Processor.");

    }

    /**
     * Notifies this subsystem if owner is in running mode.
     *
     * @exception EBaseException failed to start up
     */
    @Override
    public void startup() throws EBaseException {

        // Note that we use our instance id for registration.
        // This helps us to support multiple instances
        // of a subsystem within server.

    }

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    @Override
    public void shutdown() {
        logger.info("TKSAuthority is stopped");
    }

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    @Override
    public TKSConfig getConfigStore() {
        return mConfig;
    }

    @Override
    public String getId() {
        return mId;
    }

    /**
     * Sets subsystem identifier.
     *
     * @param id subsystem id
     * @exception EBaseException failed to set id
     */
    @Override
    public void setId(String id) throws EBaseException {
        mId = id;
    }
}

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
package com.netscape.cms.authentication;

import org.dogtagpki.server.authentication.AuthManagerProxy;

import com.netscape.certsrv.authentication.AuthMgrPlugin;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.authentication.AuthSubsystem;

/**
 * CA authentication subsystem
 *
 * @author cfu
 * @author lhsiao
 */
public class CAAuthSubsystem extends AuthSubsystem {

    /**
     * Constant for challenge based authentication plugin ID.
     */
    public final static String CHALLENGE_PLUGIN_ID = "challengeAuthPlugin";

    /**
     * Constant for ssl client authentication plugin ID.
     */
    public final static String SSLCLIENTCERT_PLUGIN_ID = "sslClientCertAuthPlugin";

    /**
     * Constant for challenge based authentication manager ID.
     */
    public final static String CHALLENGE_AUTHMGR_ID = "challengeAuthMgr";

    /**
     * Constant for ssl client authentication manager ID.
     */
    public final static String SSLCLIENTCERT_AUTHMGR_ID = "sslClientCertAuthMgr";

    public CAAuthSubsystem() {
    }

    public void loadAuthManagerPlugins() throws EBaseException {

        super.loadAuthManagerPlugins();

        logger.info("CAAuthSubsystem: Loading auth manager plugin " + CHALLENGE_PLUGIN_ID);

        AuthMgrPlugin plugin = new AuthMgrPlugin(CHALLENGE_PLUGIN_ID, ChallengePhraseAuthentication.class.getName());
        plugin.setVisible(false);
        mAuthMgrPlugins.put(CHALLENGE_PLUGIN_ID, plugin);

        logger.info("CAAuthSubsystem: Loading auth manager plugin " + SSLCLIENTCERT_PLUGIN_ID);

        plugin = new AuthMgrPlugin(SSLCLIENTCERT_PLUGIN_ID, SSLClientCertAuthentication.class.getName());
        plugin.setVisible(false);
        mAuthMgrPlugins.put(SSLCLIENTCERT_PLUGIN_ID, plugin);
    }

    public void loadAuthManagerInstances() throws EBaseException {

        super.loadAuthManagerInstances();

        logger.info("CAAuthSubsystem: Loading auth manager instance " + CHALLENGE_AUTHMGR_ID);

        ChallengePhraseAuthentication challengeAuth = new ChallengePhraseAuthentication();
        challengeAuth.setCMSEngine(engine);
        challengeAuth.init(mConfig, CHALLENGE_AUTHMGR_ID, CHALLENGE_PLUGIN_ID, null);
        mAuthMgrInsts.put(CHALLENGE_AUTHMGR_ID, new AuthManagerProxy(true, challengeAuth));

        logger.info("CAAuthSubsystem: Loading auth manager instance " + SSLCLIENTCERT_AUTHMGR_ID);

        SSLClientCertAuthentication sslClientCertAuth = new SSLClientCertAuthentication();
        sslClientCertAuth.setCMSEngine(engine);
        sslClientCertAuth.init(mConfig, SSLCLIENTCERT_AUTHMGR_ID, SSLCLIENTCERT_PLUGIN_ID, null);
        mAuthMgrInsts.put(SSLCLIENTCERT_AUTHMGR_ID, new AuthManagerProxy(true, sslClientCertAuth));
    }
}

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
package com.netscape.cmscore.ldap;

import netscape.ldap.LDAPConnection;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapBoundConnFactory;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.ldap.ILdapConnInfo;
import com.netscape.certsrv.ldap.ILdapConnModule;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.LdapConnInfo;

public class LdapConnModule implements ILdapConnModule {
    protected IConfigStore mConfig = null;
    protected LdapBoundConnFactory mLdapConnFactory = null;
    protected ILogger mLogger = CMS.getLogger();
    private boolean mInited = false;

    /**
     * instantiate connection factory.
     */

    public static final String PROP_LDAP = "ldap";

    public LdapConnModule() {
    }

    public LdapConnModule(LdapBoundConnFactory factory) {
        mLdapConnFactory = factory;
        mInited = true;
    }

    protected ISubsystem mPubProcessor;

    public void init(ISubsystem p,
            IConfigStore config)
            throws EBaseException {

        CMS.debug("LdapConnModule: init called");
        if (mInited) {
            CMS.debug("LdapConnModule: already initialized. return.");
            return;
        }
        CMS.debug("LdapConnModule: init begins");

        mPubProcessor = p;
        mConfig = config;
        /*
        mLdapConnFactory = new LdapBoundConnFactory();
        mLdapConnFactory.init(mConfig.getSubStore("ldap"));
        */

        // support publishing dirsrv with different pwd than internaldb
        IConfigStore ldap = mConfig.getSubStore("ldap");

        IConfigStore ldapconn = ldap.getSubStore(
                         ILdapBoundConnFactory.PROP_LDAPCONNINFO);
        IConfigStore authinfo = ldap.getSubStore(
                         ILdapBoundConnFactory.PROP_LDAPAUTHINFO);
        ILdapConnInfo connInfo =
                CMS.getLdapConnInfo(ldapconn);
        LdapAuthInfo authInfo =
                new LdapAuthInfo(authinfo, ldapconn.getString("host"),
                        ldapconn.getInteger("port"), connInfo.getSecure());

        int minConns = mConfig.getInteger(ILdapBoundConnFactory.PROP_MINCONNS, 3);
        int maxConns = mConfig.getInteger(ILdapBoundConnFactory.PROP_MAXCONNS, 15);
        // must get authInfo from the config, don't default to internaldb!!!

        CMS.debug("Creating LdapBoundConnFactory for LdapConnModule.");
        mLdapConnFactory =
                new LdapBoundConnFactory(minConns, maxConns, (LdapConnInfo) connInfo, authInfo);

        mInited = true;

        CMS.debug("LdapConnModule: init ends");
    }

    /**
     * Returns the internal ldap connection factory.
     * This can be useful to get a ldap connection to the
     * ldap publishing directory without having to get it again from the
     * config file. Note that this means sharing a ldap connection pool
     * with the ldap publishing module so be sure to return connections to pool.
     * Use ILdapConnFactory.getConn() to get a Ldap connection to the ldap
     * publishing directory.
     * Use ILdapConnFactory.returnConn() to return the connection.
     *
     * @see com.netscape.certsrv.ldap.ILdapBoundConnFactory
     * @see com.netscape.certsrv.ldap.ILdapConnFactory
     */
    public ILdapConnFactory getLdapConnFactory() {
        return mLdapConnFactory;
    }

    public LDAPConnection getConn() throws ELdapException {
        return mLdapConnFactory.getConn();
    }

    public void returnConn(LDAPConnection conn) throws ELdapException {
        mLdapConnFactory.returnConn(conn);
    }

    public void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_LDAP, level,
                "LdapPublishModule: " + msg);
    }

}

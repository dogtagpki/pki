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
package com.netscape.cmscore.ldapconn;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSocketFactory;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.ldap.ILdapBoundConnFactory;
import com.netscape.certsrv.logging.ILogger;

/**
 * Factory for getting LDAP Connections to a LDAP server with the same
 * LDAP authentication.
 * XXX not sure how useful this is given that LDAPConnection itself can
 * be shared by multiple threads and cloned.
 */
public class LdapBoundConnFactory implements ILdapBoundConnFactory {
    protected int mMinConns = 5;
    protected int mMaxConns = 1000;
    protected LdapConnInfo mConnInfo = null;
    protected LdapAuthInfo mAuthInfo = null;

    private ILogger mLogger = CMS.getLogger();

    public static final String PROP_MINCONNS = "minConns";
    public static final String PROP_MAXCONNS = "maxConns";
    public static final String PROP_LDAPCONNINFO = "ldapconn";
    public static final String PROP_LDAPAUTHINFO = "ldapauth";

    public static final String PROP_ERROR_IF_DOWN = "errorIfDown";

    private int mNumConns = 0; // number of available conns in array
    private int mTotal = 0; // total num conns

    private boolean doCloning = true;
    private LdapBoundConnection mMasterConn = null; // master connection object.
    private BoundConnection mConns[];

    /**
     * return error if server is down at creation time.
     */
    private boolean mErrorIfDown;

    /**
     * default value for the above at init time.
     */
    private boolean mDefErrorIfDown = false;

    /**
     * Constructor for initializing from the config store.
     * must be followed by init(IConfigStore)
     */
    public LdapBoundConnFactory() {
    }

    public LdapBoundConnFactory(boolean defErrorIfDown) {
        mDefErrorIfDown = defErrorIfDown;
    }

    public int totalConn() {
        return mTotal;
    }

    public synchronized int freeConn() {
        return mNumConns;
    }

    public int maxConn() {
        return mMaxConns;
    }

    /**
     * Constructor for LdapBoundConnFactory
     *
     * @param minConns minimum number of connections to have available
     * @param maxConns max number of connections to have available. This is
     *            the maximum number of clones of this connection or separate connections one wants to allow.
     * @param serverInfo server connection info - host, port, etc.
     */
    public LdapBoundConnFactory(int minConns, int maxConns,
            LdapConnInfo connInfo, LdapAuthInfo authInfo) throws ELdapException {
        init(minConns, maxConns, connInfo, authInfo);
    }

    /**
     * Constructor for initialize
     */
    public void init(IConfigStore config)
            throws ELdapException, EBaseException {

        CMS.debug("LdapBoundConnFactory: init ");
        LdapConnInfo connInfo =
                new LdapConnInfo(config.getSubStore(PROP_LDAPCONNINFO));

        mErrorIfDown = config.getBoolean(PROP_ERROR_IF_DOWN, mDefErrorIfDown);

        doCloning = config.getBoolean("doCloning", true);

        CMS.debug("LdapBoundConnFactory:doCloning " + doCloning);
        init(config.getInteger(PROP_MINCONNS, mMinConns),
                config.getInteger(PROP_MAXCONNS, mMaxConns),
                connInfo,
                new LdapAuthInfo(config.getSubStore(PROP_LDAPAUTHINFO),
                        connInfo.getHost(), connInfo.getPort(), connInfo.getSecure()));
    }

    /**
     * initialize parameters obtained from either constructor or
     * config store
     *
     * @param minConns minimum number of connection handls to have available.
     * @param maxConns maximum total number of connections to ever have.
     * @param connInfo ldap connection info.
     * @param authInfo ldap authentication info.
     * @exception ELdapException if any error occurs.
     */
    private void init(int minConns, int maxConns,
            LdapConnInfo connInfo, LdapAuthInfo authInfo)
            throws ELdapException {
        if (minConns <= 0 || maxConns <= 0 || minConns > maxConns)
            throw new ELdapException(
                    CMS.getUserMessage("CMS_LDAP_INVALID_NUMCONN_PARAMETERS"));
        if (connInfo == null || authInfo == null)
            throw new IllegalArgumentException("connInfo or authInfo is null!");

        mMinConns = minConns;
        mMaxConns = maxConns;
        mConnInfo = connInfo;
        mAuthInfo = authInfo;

        mConns = new BoundConnection[mMaxConns];

        // Create connection handle and make initial connection
        CMS.debug(
                "init: before makeConnection errorIfDown is " + mErrorIfDown);
        makeConnection(mErrorIfDown);

        CMS.debug(
                "initializing with mininum " + mMinConns + " and maximum " + mMaxConns +
                        " connections to " +
                        "host " + mConnInfo.getHost() + " port " + mConnInfo.getPort() +
                        ", secure connection, " + mConnInfo.getSecure() +
                        ", authentication type " + mAuthInfo.getAuthType());

        // initalize minimum number of connection handles available.
        makeMinimum();
    }

    /**
     * makes the initial master connection used to clone others..
     *
     * @exception ELdapException if any error occurs.
     */
    protected void makeConnection(boolean errorIfDown) throws ELdapException {
        CMS.debug("makeConnection: errorIfDown " + errorIfDown);
        try {
            mMasterConn = new BoundConnection(mConnInfo, mAuthInfo);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAPCONN_CONNECT_SERVER",
                                mConnInfo.getHost(),
                                Integer.toString(mConnInfo.getPort())));
                if (errorIfDown) {
                    throw new ELdapServerDownException(
                            CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE",
                                    mConnInfo.getHost(), "" + mConnInfo.getPort()));
                }
            } else {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAPCONN_FAILED_SERVER", e.toString()));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_CONNECT_TO_LDAP_SERVER_FAILED",
                                mConnInfo.getHost(), "" + (Integer.valueOf(mConnInfo.getPort())), e.toString()));
            }
        }
    }

    /**
     * makes subsequent connections if cloning is not used .
     *
     * @exception ELdapException if any error occurs.
     */
    private LdapBoundConnection makeNewConnection(boolean errorIfDown) throws ELdapException {
        CMS.debug("LdapBoundConnFactory:In makeNewConnection: errorIfDown " + errorIfDown);
        LdapBoundConnection conn = null;
        try {
            conn = new BoundConnection(mConnInfo, mAuthInfo);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAPCONN_CONNECT_SERVER",
                                mConnInfo.getHost(),
                                Integer.toString(mConnInfo.getPort())));
                if (errorIfDown) {
                    throw new ELdapServerDownException(
                            CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE",
                                    mConnInfo.getHost(), "" + mConnInfo.getPort()));
                }
            } else {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAPCONN_FAILED_SERVER", e.toString()));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_CONNECT_TO_LDAP_SERVER_FAILED",
                                mConnInfo.getHost(), "" + (Integer.valueOf(mConnInfo.getPort())), e.toString()));
            }
        }

        return conn;
    }

    /**
     * makes the minumum number of connections
     */
    private void makeMinimum() throws ELdapException {
        if (mMasterConn == null || mMasterConn.isConnected() == false)
            return;
        int increment;

        if (mNumConns < mMinConns && mTotal <= mMaxConns) {
            increment = Math.min(mMinConns - mNumConns, mMaxConns - mTotal);
            CMS.debug(
                    "increasing minimum connections by " + increment);
            for (int i = increment - 1; i >= 0; i--) {

                if (doCloning == true) {
                    mConns[i] = (BoundConnection) mMasterConn.clone();
                } else {
                    mConns[i] = (BoundConnection) makeNewConnection(true);
                }

            }
            mTotal += increment;
            mNumConns += increment;
            CMS.debug("new total available connections " + mTotal);
            CMS.debug("new number of connections " + mNumConns);
        }
    }

    /**
     * gets a conenction from this factory.
     * All connections obtained from the factory must be returned by
     * returnConn() method.
     * The best thing to do is to put returnConn in a finally clause so it
     * always gets called. For example,
     *
     * <pre>
     * LDAPConnection c = null;
     * try {
     *     c = factory.getConn();
     *     myclass.do_something_with_c(c);
     * } catch (ELdapException e) {
     *     handle_error_here();
     * } finally {
     *     factory.returnConn(c);
     * }
     * </pre>
     */
    public LDAPConnection getConn()
            throws ELdapException {
        return getConn(true);
    }

    /**
     * Returns a LDAP connection - a clone of the master connection.
     * All connections should be returned to the factory using returnConn()
     * to recycle connection objects.
     * If not returned the limited max number is affected but if that
     * number is large not much harm is done.
     * Returns null if maximum number of connections reached.
     * The best thing to do is to put returnConn in a finally clause so it
     * always gets called. For example,
     *
     * <pre>
     * LDAPConnection c = null;
     * try {
     *     c = factory.getConn();
     *     myclass.do_something_with_c(c);
     * } catch (ELdapException e) {
     *     handle_error_here();
     * } finally {
     *     factory.returnConn(c);
     * }
     * </pre>
     */
    public synchronized LDAPConnection getConn(boolean waitForConn)
            throws ELdapException {
        boolean waited = false;

        CMS.debug("In LdapBoundConnFactory::getConn()");
        if (mMasterConn != null)
            CMS.debug("masterConn is connected: " + mMasterConn.isConnected());
        else
            CMS.debug("masterConn is null.");

        if (mMasterConn == null || !mMasterConn.isConnected()) {
            try {
                makeConnection(true);
            } catch (ELdapException e) {
                mMasterConn = null;
                CMS.debug("Can't create master connection in LdapBoundConnFactory::getConn! " + e.toString());
                throw e;
            }
        }

        if (mNumConns == 0)
            makeMinimum();
        if (mNumConns == 0) {
            if (!waitForConn)
                return null;
            try {
                CMS.debug("getConn: out of ldap connections");
                log(ILogger.LL_WARN,
                        "Ran out of ldap connections available " +
                                "in ldap connection pool to " +
                                mConnInfo.getHost() + ":" + mConnInfo.getPort() + ". " +
                                "This could be a temporary condition or an indication of " +
                                "something more serious that can cause the server to " +
                                "hang.");
                waited = true;
                while (mNumConns == 0)
                    wait();
            } catch (InterruptedException e) {
            }
        }
        mNumConns--;
        LDAPConnection conn = mConns[mNumConns];

        boolean isConnected = false;
        if (conn != null) {
            isConnected = conn.isConnected();
        }

        CMS.debug("getConn: conn is connected " + isConnected);

        //If masterConn is still alive, lets try to bring this one
        //back to life

        if ((isConnected == false) && (mMasterConn != null)
                && (mMasterConn.isConnected() == true)) {
            CMS.debug("Attempt to bring back down connection.");

            if (doCloning == true) {
                mConns[mNumConns] = (BoundConnection) mMasterConn.clone();
            } else {
                try {
                    mConns[mNumConns] = (BoundConnection) makeNewConnection(true);
                } catch (ELdapException e) {
                    mConns[mNumConns] = null;
                }
            }
            conn = mConns[mNumConns];

            CMS.debug("Re-animated connection: " + conn);
        }

        mConns[mNumConns] = null;

        if (waited) {
            log(ILogger.LL_WARN,
                    "Ldap connections are available again in ldap connection pool " +
                            "to " + mConnInfo.getHost() + ":" + mConnInfo.getPort());
        }
        CMS.debug("getConn: mNumConns now " + mNumConns);

        return conn;
    }

    /**
     * Teturn connection to the factory.
     * This is mandatory after a getConn().
     * The best thing to do is to put returnConn in a finally clause so it
     * always gets called. For example,
     *
     * <pre>
     * LDAPConnection c = null;
     * try {
     *     c = factory.getConn();
     *     myclass.do_something_with_c(c);
     * } catch (ELdapException e) {
     *     handle_error_here();
     * } finally {
     *     factory.returnConn(c);
     * }
     * </pre>
     */
    public synchronized void returnConn(LDAPConnection conn) {
        if (conn == null) {
            return;
        }
        BoundConnection boundconn = null;

        if (conn instanceof BoundConnection) {
            boundconn = (BoundConnection) conn;
        } else {
            log(ILogger.LL_WARN, "returnConn : Connection is not an BoundConnection");
            return;
        }

        if (boundconn.getFacId() != mConns) {
            log(ILogger.LL_WARN, "returnConn: unknown connection.");
        }
        for (int i = 0; i < mNumConns; i++) {
            if (mConns[i] == conn) {
                CMS.debug(
                        "returnConn: previously returned connection.");
            }
        }
        mConns[mNumConns++] = boundconn;
        CMS.debug("returnConn: mNumConns now " + mNumConns);
        notify();
    }

    /**
     * handy routine for logging in this class.
     */
    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
                "In Ldap (bound) connection pool to" +
                        " host " + mConnInfo.getHost() +
                        " port " + mConnInfo.getPort() + ", " + msg);
    }

    protected void finalize()
            throws Exception {
        reset();
    }

    /**
     * used for disconnecting all connections and reset everything to 0
     * as if connections were never made. used just before a subsystem
     * shutdown or process exit.
     * useful only if no connections are outstanding.
     */
    public synchronized void reset()
            throws ELdapException {
        if (mNumConns == mTotal) {
            for (int i = 0; i < mNumConns; i++) {
                try {
                    mConns[i].disconnect();
                } catch (LDAPException e) {
                }
                mConns[i] = null;
            }
            if (mMasterConn != null) {
                try {
                    log(ILogger.LL_INFO, "disconnecting masterConn");
                    mMasterConn.disconnect();
                } catch (LDAPException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_LDAPCONN_CANNOT_RESET",
                                    e.toString()));
                }
            }
            mMasterConn = null;
            mTotal = 0;
            mNumConns = 0;
        } else {
            CMS.debug(
                    "Cannot reset factory: connections not all returned");
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_CANNOT_RESET_CONNFAC"));
        }

        if (mAuthInfo != null) {
            mAuthInfo.reset();
        }
    }

    /**
     * return ldap connection info
     */
    public LdapConnInfo getConnInfo() {
        return mConnInfo;
    }

    /**
     * return ldap authentication info
     */
    public LdapAuthInfo getAuthInfo() {
        return mAuthInfo;
    }

    /**
     * used to keep track of connections from this factory.
     */
    public class BoundConnection extends LdapBoundConnection {
        /**
         *
         */
        private static final long serialVersionUID = 1353616391879078337L;

        public BoundConnection(LdapConnInfo connInfo, LdapAuthInfo authInfo)
                throws LDAPException {
            super(connInfo, authInfo);
        }

        public BoundConnection(String host, int port, int version,
                LDAPSocketFactory fac,
                String bindDN, String bindPW)
                throws LDAPException {
            super(host, port, version, fac, bindDN, bindPW);
        }

        /**
         * used only to identify the factory from which this came.
         */
        public BoundConnection[] getFacId() {
            return mConns;
        }
    }
}

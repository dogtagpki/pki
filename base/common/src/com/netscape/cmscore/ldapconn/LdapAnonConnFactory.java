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
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;

/**
 * Factory for getting LDAP Connections to a LDAP server
 * each connection is a seperate thread that can be bound to a different
 * authentication dn and password.
 */
public class LdapAnonConnFactory implements ILdapConnFactory {
    protected int mMinConns = 5;
    protected int mMaxConns = 1000;
    protected LdapConnInfo mConnInfo = null;

    private ILogger mLogger = CMS.getLogger();

    public static final String PROP_MINCONNS = "minConns";
    public static final String PROP_MAXCONNS = "maxConns";
    public static final String PROP_LDAPCONNINFO = "ldapconn";

    public static final String PROP_ERROR_IF_DOWN = "errorIfDown";

    private int mNumConns = 0; // number of available conns in array
    private int mTotal = 0; // total num conns
    private AnonConnection mConns[] = null;

    private boolean mInited = false;

    private boolean mErrorIfDown;
    private boolean mDefErrorIfDown = false;

    /**
     * Constructor for initializing from the config store.
     * must be followed by init(IConfigStore)
     */
    public LdapAnonConnFactory() {
    }

    public LdapAnonConnFactory(boolean defErrorIfDown) {
        mDefErrorIfDown = defErrorIfDown;
    }

    /**
     * Constructor for LdapAnonConnFactory
     *
     * @param minConns minimum number of connections to have available
     * @param maxConns max number of connections to have available. This is
     *            the maximum number of clones of this connection one wants to allow.
     * @param serverInfo server connection info - host, port, etc.
     */
    public LdapAnonConnFactory(int minConns, int maxConns,
            LdapConnInfo connInfo) throws ELdapException {
        init(minConns, maxConns, connInfo);
    }

    public int totalConn() {
        return mTotal;
    }

    public int freeConn() {
        return mNumConns;
    }

    public int maxConn() {
        return mMaxConns;
    }

    /**
     * init routine to be called when initialize from config store.
     */
    public void init(IConfigStore config) throws EBaseException, ELdapException {
        String minStr = config.getString(PROP_MINCONNS, "");
        String maxStr = config.getString(PROP_MAXCONNS, "");
        int minConns = mMinConns;
        int maxConns = mMaxConns;

        // if it is "", use the default value
        if (!minStr.equals("")) {
            try {
                minConns = Integer.parseInt(minStr);
            } catch (NumberFormatException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAPCONN_MIN_CONN"));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_NUMBER_FORMAT_1", PROP_MINCONNS));
            }
        }

        // if it is "", use the default value
        if (!maxStr.equals("")) {
            try {
                maxConns = Integer.parseInt(maxStr);
            } catch (NumberFormatException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAPCONN_MAX_CONN"));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_NUMBER_FORMAT_1", PROP_MAXCONNS));
            }
        }

        mErrorIfDown = config.getBoolean(PROP_ERROR_IF_DOWN, mDefErrorIfDown);

        init(minConns, maxConns,
                new LdapConnInfo(config.getSubStore(PROP_LDAPCONNINFO)));
    }

    /**
     * initialize routine from parameters.
     */
    protected void init(int minConns, int maxConns, LdapConnInfo connInfo)
            throws ELdapException {
        if (mInited)
            return; // XXX should throw exception here ?

        if (minConns <= 0 || maxConns <= 0 || minConns > maxConns)
            throw new ELdapException(
                    CMS.getUserMessage("CMS_LDAP_INVALID_NUMCONN_PARAMETERS"));
        if (connInfo == null)
            throw new IllegalArgumentException("connInfo is Null!");

        mMinConns = minConns;
        mMaxConns = maxConns;
        mConnInfo = connInfo;

        mConns = new AnonConnection[mMaxConns];

        log(ILogger.LL_INFO,
                "Created: min " + minConns + " max " + maxConns +
                        " host " + connInfo.getHost() + " port " + connInfo.getPort() +
                        " secure " + connInfo.getSecure());

        // initalize minimum number of connection handles available.
        makeMinimum(mErrorIfDown);
        mInited = true;
    }

    /**
     * make the mininum configured connections
     */
    protected void makeMinimum(boolean errorIfDown) throws ELdapException {
        try {
            if (mNumConns < mMinConns && mTotal < mMaxConns) {
                int increment = Math.min(mMinConns - mNumConns, mMaxConns - mTotal);

                CMS.debug(
                        "increasing minimum number of connections by " + increment);
                for (int i = increment - 1; i >= 0; i--) {
                    mConns[i] = new AnonConnection(mConnInfo);
                }
                mTotal += increment;
                mNumConns += increment;
                CMS.debug(
                        "new total number of connections " + mTotal);
                CMS.debug(
                        "new total available connections " + mNumConns);
            }
        } catch (LDAPException e) {
            // XXX errorCodeToString() used here so users won't see message.
            // though why are messages from exceptions being displayed to
            // users ?
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                        "Cannot connect to Ldap server. Error: " +
                                "Ldap Server host " + mConnInfo.getHost() +
                                " int " + mConnInfo.getPort() + " is unavailable.");
                if (errorIfDown) {
                    throw new ELdapServerDownException(
                            CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE",
                                    mConnInfo.getHost(), "" + mConnInfo.getPort()));
                }
            } else {
                log(ILogger.LL_FAILURE,
                        "Cannot connect to ldap server. error: " + e.toString());
                String errmsg = e.errorCodeToString();

                if (errmsg == null)
                    errmsg = e.toString();
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_CONNECT_TO_LDAP_SERVER_FAILED",
                                mConnInfo.getHost(), "" + (Integer.valueOf(mConnInfo.getPort())), errmsg));
            }
        }
    }

    /**
     * Gets connection from this factory.
     * All connections gotten from this factory must be returned.
     * If not the max number of connections may be reached prematurely.
     * The best thing to put returnConn in a finally clause so it
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
     * <p>
     * The best thing to put returnConn in a finally clause so it always gets called. For example,
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

        CMS.debug("LdapAnonConnFactory::getConn");
        if (mNumConns == 0)
            makeMinimum(true);
        if (mNumConns == 0) {
            if (!waitForConn)
                return null;
            try {
                CMS.debug("getConn(): out of ldap connections");
                log(ILogger.LL_WARN,
                        "Ran out of ldap connections available " +
                                "in ldap connection pool to " +
                                mConnInfo.getHost() + ":" + mConnInfo.getPort() + ". " +
                                "This could be a temporary condition or an indication of " +
                                "something more serious that can cause the server to " +
                                "hang.");
                waited = true;
                while (mNumConns == 0) {
                    wait();
                }
            } catch (InterruptedException e) {
            }
        }

        mNumConns--;
        AnonConnection conn = mConns[mNumConns];

        mConns[mNumConns] = null;
        if (waited) {
            log(ILogger.LL_WARN,
                    "Ldap connections are available again in ldap connection pool " +
                            "to " + mConnInfo.getHost() + ":" + mConnInfo.getPort());
        }
        CMS.debug("LdapAnonConnFactory.getConn(): num avail conns now " + mNumConns);
        //Beginning of fix for Bugzilla #630176
        boolean isConnected = false;
        if (conn != null) {
            isConnected = conn.isConnected();
        }

        if (!isConnected) {
            CMS.debug("LdapAnonConnFactory.getConn(): selected conn is down, try to reconnect...");
            conn = null;
            try {
                conn = new AnonConnection(mConnInfo);
            } catch (LDAPException e) {
                CMS.debug("LdapAnonConnFactory.getConn(): error when trying to bring back a down connection.");
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_CONNECT_TO_LDAP_SERVER_FAILED",
                                mConnInfo.getHost(), "" + (Integer.valueOf(mConnInfo.getPort())), e.toString()));
            }
        }
        //This is the end of the fix for Bugzilla #630176

        return conn;
    }

    /**
     * Returns a connection to the factory for recycling.
     * All connections gotten from this factory must be returned.
     * If not the max number of connections may be reached prematurely.
     * <p>
     * The best thing to put returnConn in a finally clause so it always gets called. For example,
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
        AnonConnection anon = null;

        // check if conn is valid and from this factory.
        if (conn instanceof AnonConnection) {
            anon = (AnonConnection) conn;
        } else {
            log(ILogger.LL_WARN, "returnConn : Connection is not an AnonConnection");
            return;
        }

        if (anon.getFacId() != mConns) {
            // returning a connection not from this factory.
            log(ILogger.LL_WARN, "returnConn: unknown connection.");
        }
        // check if conn has already been returned.
        for (int i = 0; i < mNumConns; i++) {
            // returning connection already returned.
            if (mConns[i] == anon) {

                /* swallow this error but see who's doing it. */
                log(ILogger.LL_WARN,
                        "returnConn: previously returned connection.");
            }
        }

        // this returned connection might authenticate as someone other than
        // anonymonus. Reset it to anonymous first before it returns
        // to the pool.  Do this by calling connect() again on this connection
        // to avoid doing an explicit anonymous bind
        try {
            anon.connect(mConnInfo.getHost(), mConnInfo.getPort());

            // return conn.
            CMS.debug("returnConn: mNumConns now " + mNumConns);
        } catch (LDAPException e) {
            log(ILogger.LL_WARN,
                    "Could not re-authenticate ldap connection to anonymous." +
                            " Error " + e);
        }
        // return the connection even if can't reauthentication anon.
        // most likely server was down.
        mConns[mNumConns++] = anon;

        notify();
    }

    protected void finalize()
            throws Exception {
        reset();
    }

    /**
     * returns connection info.
     */
    public LdapConnInfo getConnInfo() {
        return mConnInfo;
    }

    /**
     * resets this factory - if no connections outstanding,
     * disconnections all connections and resets everything to 0 as if
     * no connections were ever made. intended to be called just before
     * shutdown or exit to disconnection & cleanup connections.
     */
    // ok only if no connections outstanding.
    public synchronized void reset()
            throws ELdapException {
        if (mNumConns == mTotal) {
            for (int i = 0; i < mNumConns; i++) {
                try {
                    CMS.debug("disconnecting connection " + i);
                    mConns[i].disconnect();
                } catch (LDAPException e) {
                    log(ILogger.LL_INFO,
                            "exception during disconnect: " + e.toString());
                }
                mConns[i] = null;
            }
            mTotal = 0;
            mNumConns = 0;
        } else {
            log(ILogger.LL_INFO,
                    "Cannot reset() while connections not all returned");
            throw new ELdapException(
                    CMS.getUserMessage("CMS_LDAP_CANNOT_RESET_CONNFAC"));
        }
    }

    /**
     * handy routine for logging in this class.
     */
    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
                "In Ldap (anonymous) connection pool to" +
                        " host " + mConnInfo.getHost() +
                        " port " + mConnInfo.getPort() + ", " + msg);
    }

    /**
     * used to keep track of connections from this factory.
     */
    public class AnonConnection extends LdapAnonConnection {
        /**
         *
         */
        private static final long serialVersionUID = 4813780131074412404L;

        public AnonConnection(LdapConnInfo connInfo)
                throws LDAPException {
            super(connInfo);
        }

        public AnonConnection(String host, int port, int version,
                LDAPSocketFactory fac)
                throws LDAPException {
            super(host, port, version, fac);
        }

        /**
         * instantiates a non-secure connection to a ldap server
         */
        public AnonConnection(String host, int port, int version)
                throws LDAPException {
            super(host, port, version);
        }

        /**
         * used only to identify the factory from which this came.
         * mConns to identify factory.
         */
        public AnonConnection[] getFacId() {
            return mConns;
        }
    }
}

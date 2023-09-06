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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.ldap.LdapConnFactory;
import com.netscape.cmsutil.password.PasswordStore;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPv3;

/**
 * Factory for getting LDAP Connections to a LDAP server with the same
 * LDAP authentication.
 *
 * Maintains a pool of connections to the LDAP server.
 * CMS requests are processed on a multi threaded basis.
 * A pool of connections then must be be maintained so this
 * access to the Ldap server can be easily managed. The min and
 * max size of this connection pool should be configurable. Once
 * the maximum limit of connections is exceeded, the factory
 * should provide proper synchronization to resolve contention issues.
 *
 * XXX not sure how useful this is given that LDAPConnection itself can
 * be shared by multiple threads and cloned.
 */
public class LdapBoundConnFactory extends LdapConnFactory {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapBoundConnFactory.class);

    protected String id;

    PKISocketConfig config;

    protected int mMinConns = 5;
    protected int mMaxConns = 1000;
    protected int mMaxResults = 0;

    protected LdapConnInfo mConnInfo = null;
    protected LdapAuthInfo mAuthInfo = null;
    PasswordStore passwordStore;

    public static final String PROP_MINCONNS = "minConns";
    public static final String PROP_MAXCONNS = "maxConns";
    public static final String PROP_MAXRESULTS = "maxResults";
    public static final String PROP_LDAPCONNINFO = "ldapconn";
    public static final String PROP_LDAPAUTHINFO = "ldapauth";

    public static final String PROP_ERROR_IF_DOWN = "errorIfDown";

    private int mNumConns = 0; // number of available conns in array
    private int mTotal = 0; // total num conns

    private boolean doCloning = true;
    private LdapBoundConnection mMasterConn = null; // master connection object.
    private LdapBoundConnection[] mConns;

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
     * must be followed by init(ConfigStore)
     */
    public LdapBoundConnFactory(String id) {
        logger.debug("Creating LdapBoundConnFactor(" + id + ")");
        this.id = id;
    }

    public LdapBoundConnFactory(String id, boolean defErrorIfDown) {
        logger.debug("Creating LdapBoundConnFactor(" + id + ")");
        this.id = id;
        mDefErrorIfDown = defErrorIfDown;
    }

    /**
     * Constructor for LdapBoundConnFactory
     *
     * @param minConns minimum number of connections to have available
     * @param maxConns max number of connections to have available. This is
     *            the maximum number of clones of this connection or separate connections one wants to allow.
     * @param connInfo server connection info - host, port, etc.
     */
    public LdapBoundConnFactory(
            String id,
            int minConns,
            int maxConns,
            LdapConnInfo connInfo,
            LdapAuthInfo authInfo
            ) throws ELdapException {

        logger.debug("Creating LdapBoundConnFactory(" + id + ")");

        this.id = id;

        this.mMinConns = minConns;
        this.mMaxConns = maxConns;
        this.mConnInfo = connInfo;
        this.mAuthInfo = authInfo;
    }

    /**
     * Constructor for LdapBoundConnFactory
     *
     * @param minConns minimum number of connections to have available
     * @param maxConns max number of connections to have available. This is
     *            the maximum number of clones of this connection or separate connections one wants to allow.
     * @param maxResults max number of results to return per query
     * @param connInfo server connection info - host, port, etc.
     */
    public LdapBoundConnFactory(
            String id,
            int minConns,
            int maxConns,
            int maxResults,
            LdapConnInfo connInfo,
            LdapAuthInfo authInfo
            ) throws ELdapException {

        logger.debug("Creating LdapBoundConnFactory(" + id + ")");

        this.id = id;

        this.mMinConns = minConns;
        this.mMaxConns = maxConns;
        this.mMaxResults = maxResults;

        this.mConnInfo = connInfo;
        this.mAuthInfo = authInfo;
    }

    @Override
    public int totalConn() {
        return mTotal;
    }

    @Override
    public synchronized int freeConn() {
        return mNumConns;
    }

    @Override
    public int maxConn() {
        return mMaxConns;
    }

    public void init(
            PKISocketConfig config,
            PasswordStore passwordStore
            ) throws ELdapException {

        logger.debug("LdapBoundConnFactory: initialization");

        this.config = config;
        this.passwordStore = passwordStore;

        init();
    }

    public void init(
            PKISocketConfig config,
            LDAPConfig dbConfig,
            PasswordStore passwordStore
            ) throws EBaseException, ELdapException {

        this.passwordStore = passwordStore;

        init(config, dbConfig);
    }

    public void init(PKISocketConfig config, LDAPConfig dbConfig) throws EBaseException, ELdapException {

        logger.debug("LdapBoundConnFactory: initialization");

        this.config = config;

        this.mMinConns = dbConfig.getInteger(PROP_MINCONNS, mMinConns);
        this.mMaxConns = dbConfig.getInteger(PROP_MAXCONNS, mMaxConns);
        this.mMaxResults = dbConfig.getInteger(PROP_MAXRESULTS, mMaxResults);

        LDAPConnectionConfig connConfig = dbConfig.getConnectionConfig();
        this.mConnInfo = new LdapConnInfo(connConfig);

        LDAPAuthenticationConfig authConfig = dbConfig.getAuthenticationConfig();
        this.mAuthInfo = new LdapAuthInfo();
        this.mAuthInfo.setPasswordStore(passwordStore);

        this.mAuthInfo.init(
                authConfig,
                this.mConnInfo.getHost(),
                this.mConnInfo.getPort(),
                this.mConnInfo.getSecure());

        mErrorIfDown = dbConfig.getBoolean(PROP_ERROR_IF_DOWN, mDefErrorIfDown);

        doCloning = dbConfig.getBoolean("doCloning", true);
        logger.debug("LdapBoundConnFactory: doCloning: " + doCloning);

        init();
    }

    /**
     * initialize parameters obtained from either constructor or
     * config store
     */
    private void init() throws ELdapException {

        if (mMinConns < 0)
            throw new ELdapException("Invalid minimum number of connections: " + mMinConns);

        if (mMaxConns <= 0)
            throw new ELdapException("Invalid maximum number of connections: " + mMaxConns);

        if (mMinConns > mMaxConns)
            throw new ELdapException("Minimum number of connections is bigger than maximum: " + mMinConns + " > " + mMaxConns);

        if (mMaxResults < 0)
            throw new ELdapException("Invalid maximum number of results: " + mMaxResults);

        if (mConnInfo == null)
            throw new IllegalArgumentException("Missing connection info");

        if (mAuthInfo == null)
            throw new IllegalArgumentException("Missing authentication info");

        logger.debug("LdapBoundConnFactory: mininum: " + mMinConns);
        logger.debug("LdapBoundConnFactory: maximum: " + mMaxConns);
        logger.debug("LdapBoundConnFactory: host: " + mConnInfo.getHost());
        logger.debug("LdapBoundConnFactory: port: " + mConnInfo.getPort());
        logger.debug("LdapBoundConnFactory: secure: " + mConnInfo.getSecure());
        logger.debug("LdapBoundConnFactory: authentication: " + mAuthInfo.getAuthType());

        mConns = new LdapBoundConnection[mMaxConns];

        if (mMinConns > 0) {
            // Create connection handle and make initial connection
            makeConnection(mErrorIfDown);

            // initalize minimum number of connection handles available.
            makeMinimum();
        }
    }

    /**
     * makes the initial master connection used to clone others..
     *
     * @exception ELdapException if any error occurs.
     */
    protected void makeConnection(boolean errorIfDown) throws ELdapException {

        logger.debug("LdapBoundConnFactory: makeConnection(" + errorIfDown + ")");

       mMasterConn = makeNewConnection(errorIfDown);
       if (mMasterConn != null) {
           mMasterConn.connectionFactory = this;
       }
    }

    /**
     * makes subsequent connections if cloning is not used .
     *
     * @exception ELdapException if any error occurs.
     */
    private LdapBoundConnection makeNewConnection(boolean errorIfDown) throws ELdapException {

        logger.debug("LdapBoundConnFactory: makeNewConnection(" + errorIfDown + ")");

        LdapBoundConnection conn = null;
        try {
            PKISocketFactory socketFactory = new PKISocketFactory();
            socketFactory.setAuditor(auditor);
            if (socketListener != null) {
                socketFactory.addSocketListener(socketListener);
            }
            socketFactory.setApprovalCallback(approvalCallback);
            socketFactory.setSecure(mConnInfo.getSecure());
            if (mAuthInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
                socketFactory.setClientCertNickname(mAuthInfo.getClientCertNickname());
            }
            socketFactory.init(config);

            conn = new LdapBoundConnection(socketFactory, mConnInfo, mAuthInfo);
            conn.connectionFactory = this;

        } catch (EBaseException e) {
            throw new ELdapException("Unable to create socket factory: " + e.getMessage(), e);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                String message = "LDAP server is unavailable: " + mConnInfo.getHost() + ":" + mConnInfo.getPort();
                logger.error("LdapBoundConnFactory: " + message, e);
                if (errorIfDown) {
                    throw new ELdapServerDownException(message, e);
                }
            } else {
                String message = "Unable to connect to LDAP server: " + e.getMessage();
                logger.error("LdapBoundConnFactory: " + message, e);
                throw new ELdapException(message, e);
            }
        }

        return conn;
    }

    /**
     * makes the minumum number of connections
     */
    private void makeMinimum() throws ELdapException {
        String method = "LdapBoundConnFactory.makeMinimum: ";
        boolean cloning = false;
        int realMin = Math.max(mMinConns, 1);
        if (mMasterConn != null && mMasterConn.isConnected() && doCloning) {
            logger.debug(method + "connections will be cloned from the master");
            cloning = true;
        } else {
            logger.debug(method + "master conn not available.");
        }

        int increment;
        logger.debug(method + "begins: total connections: " + mTotal);
        logger.debug(method + "begins: available connections: " + mNumConns);

        if (mNumConns < realMin && mTotal <= mMaxConns) {
            increment = Math.min(realMin - mNumConns, mMaxConns - mTotal);
            logger.debug(method + "increasing minimum connections by " + increment);

            for (int i = increment - 1; i >= 0; i--) {
                mConns[i] = cloning ? (LdapBoundConnection) mMasterConn.clone() : makeNewConnection(true);
            }

            mTotal += increment;
            mNumConns += increment;

            logger.debug(method + "ends: total connections: " + mTotal);
            logger.debug(method + "ends: number of connections: " + mNumConns);
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
    @Override
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
    public synchronized LdapBoundConnection getConn(boolean waitForConn)
            throws ELdapException {
        LdapBoundConnection conn = null;
        String method = "LdapBoundConnFactory (" + id + ").getConn: ";
        logger.debug(method + "initial values. Total: " + mTotal + ", pool: " + mNumConns);

        if (mMasterConn != null)
            logger.debug(method + "master connection is connected: " + mMasterConn.isConnected());
        else
            logger.debug(method + "master connection is null");

        if ((mMasterConn == null || !mMasterConn.isConnected()) && mMinConns > 0) {
            try {
                makeConnection(true);
            } catch (ELdapException e) {
                mMasterConn = null;
                throw new ELdapException("LdapBoundConnFactory: Unable to create master connection. " + e.getMessage(), e);
            }
        }

        if (mNumConns == 0) {
            makeMinimum();
        }


        while (mNumConns == 0) {
            logger.warn("LdapBoundConnFactory: waiting connections for " + mConnInfo.getHost() + ":" + mConnInfo.getPort());
            if (!waitForConn) {
                logger.warn("LdapBoundConnFactory: out of LDAP connections");
                return null;
            }
            try {
                wait();
            } catch (InterruptedException e) {
                logger.warn("LdapBoundConnFactory: connection wait interrupted");
                return null;
            }
            if (mMinConns == 0) {
                makeMinimum();
            }
        }

        mNumConns--;
        conn = mConns[mNumConns];
        mConns[mNumConns] = null;
        logger.debug("LdapBoundConnFactory: number of connections: " + mNumConns);


        if (conn == null || !conn.isConnected()) {
            logger.debug("LdapBoundConnFactory: reestablishing connection");
            try {
                if (mMinConns > 0 &&
                        doCloning &&
                        mMasterConn != null) {
                    conn = (LdapBoundConnection) mMasterConn.clone();
                } else {
                    conn = makeNewConnection(true);
                }
            } catch (ELdapException e) {
                mTotal--;
                String message = "Unable to reestablish LDAP connection: " + e.getMessage();
                logger.error("LdapBoundConnFactory: " + message, e);
                throw new ELdapException(message, e);
            }
            logger.debug("LdapBoundConnFactory: connection reestablished");
        }



        try {
            // Before returning the connection, set the SIZELIMIT option; this
            // ensures that if the connection is recycled and the previous owner
            // changed the SIZELIMIT option to a different value, the next owner
            // always starts with the default.
            conn.setOption(LDAPv3.SIZELIMIT, mMaxResults);
        } catch (LDAPException e) {
            throw new ELdapException("Unable to set LDAP size limit: " + e.getMessage(), e);
        }
        logger.debug(method + " final values. Total: " + mTotal + ", pool: " + mNumConns);
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
    @Override
    public synchronized void returnConn(LDAPConnection conn) {
        String method = "LdapBoundConnFactory (" + id + ").returnConn: ";
        logger.debug(method + "initial values. Total: " + mTotal + ", pool: " + mNumConns);

        if (conn == null) {
            return;
        }
        LdapBoundConnection boundconn = null;

        if (conn instanceof LdapBoundConnection) {
            boundconn = (LdapBoundConnection) conn;
        } else {
            logger.warn("LdapBoundConnFactory: Unable to return connection: not a bound connection");
            return;
        }

        if (boundconn.connectionFactory != this) {
            logger.warn("LdapBoundConnFactory: Unknown connection");
            try {
                boundconn.disconnect();
            } catch(LDAPException e) {
                logger.warn("LdapBoundConnFactory: Unable to disconnect: " + e.getMessage(), e);
            }
            return;

        }

        for (int i = 0; i < mNumConns; i++) {
            if (mConns[i] == conn) {
                logger.warn("LdapBoundConnFactory: Connection already returned");
                --mTotal;
                notifyAll();
                return;
            }
        }

        if (mNumConns < mMinConns) {
            mConns[mNumConns++] = boundconn;
        } else {
            try {
                boundconn.disconnect();
            } catch(LDAPException e) {
                logger.warn("LdapBoundConnFactory: Unable to disconnect: " + e.getMessage(), e);
            }
            --mTotal;
        }
        notifyAll();
        logger.debug(method + " final values. Total: " + mTotal + ", pool: " + mNumConns);

    }

    @Override
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
    @Override
    public synchronized void reset()
            throws ELdapException {
        logger.debug("Destroying LdapBoundConnFactory(" + id + ")");
        if (mNumConns == mTotal) {
            for (int i = 0; i < mNumConns; i++) {
                try {
                    mConns[i].disconnect();
                } catch (LDAPException e) {
                    logger.warn("LdapBoundConnFactory: Unable to disconnect: " + e.getMessage(), e);
                }
                mConns[i] = null;
            }
            if (mMasterConn != null) {
                try {
                    logger.debug("LdapBoundConnFactory: disconnecting master connection");
                    mMasterConn.disconnect();
                } catch (LDAPException e) {
                    String message = "Unable to disconnect master connection: " + e.getMessage();
                    logger.warn("LdapBoundConnFactory: " + message, e);
                }
            }
            mMasterConn = null;
            mTotal = 0;
            mNumConns = 0;
            mConns = new LdapBoundConnection[mMaxConns];
        } else {
            String message = "Unable to reset LDAP connection factory due to outstanding connections";
            logger.error("LdapBoundConnFactory: " + message);
            throw new ELdapException(message);
        }

        if (mAuthInfo != null) {
            mAuthInfo.reset();
        }
    }

    public synchronized void shutdown() throws ELdapException {

        logger.debug("Destroying LdapBoundConnFactory(" + id + ")");

        for (int i = 0; i < mNumConns; i++) {
            if (mConns[i] != null) {
                mConns[i].close();
                mConns[i] = null;
            }
        }

        if (mMasterConn != null) {
            logger.debug("LdapBoundConnFactory: disconnecting master connection");
            mMasterConn.close();
            mMasterConn = null;
        }

        mTotal = 0;
        mNumConns = 0;

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

    public PasswordStore getPasswordStore() {
        return passwordStore;
    }

    public void setPasswordStore(PasswordStore passwordStore) {
        this.passwordStore = passwordStore;
    }
}

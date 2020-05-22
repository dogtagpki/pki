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
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.cmsutil.password.IPasswordStore;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPv2;

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
public class LdapBoundConnFactory implements ILdapConnFactory {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapBoundConnFactory.class);

    protected String id;

    IConfigStore config;

    protected int mMinConns = 5;
    protected int mMaxConns = 1000;
    protected int mMaxResults = 0;

    protected LdapConnInfo mConnInfo = null;
    protected LdapAuthInfo mAuthInfo = null;
    IPasswordStore passwordStore;

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
     * must be followed by init(IConfigStore)
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
    public LdapBoundConnFactory(
            String id,
            int minConns,
            int maxConns,
            LdapConnInfo connInfo,
            LdapAuthInfo authInfo
            ) throws ELdapException {

        logger.debug("Creating LdapBoundConnFactory(" + id + ")");

        this.id = id;
        this.config = config;

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
     * @param serverInfo server connection info - host, port, etc.
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
        this.config = config;

        this.mMinConns = minConns;
        this.mMaxConns = maxConns;
        this.mMaxResults = maxResults;

        this.mConnInfo = connInfo;
        this.mAuthInfo = authInfo;
    }

    public void init(
            IConfigStore config,
            IPasswordStore passwordStore
            ) throws ELdapException {

        logger.debug("LdapBoundConnFactory: initialization");

        this.config = config;
        this.passwordStore = passwordStore;

        init();
    }

    public void init(
            IConfigStore config,
            LDAPConfig dbConfig,
            IPasswordStore passwordStore
            ) throws EBaseException, ELdapException {

        this.passwordStore = passwordStore;

        init(config, dbConfig);
    }

    public void init(IConfigStore config, LDAPConfig dbConfig) throws EBaseException, ELdapException {

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

        if (mMinConns <= 0)
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

        // Create connection handle and make initial connection
        makeConnection(mErrorIfDown);

        // initalize minimum number of connection handles available.
        makeMinimum();
    }

    /**
     * makes the initial master connection used to clone others..
     *
     * @exception ELdapException if any error occurs.
     */
    protected void makeConnection(boolean errorIfDown) throws ELdapException {

        logger.debug("LdapBoundConnFactory: makeConnection(" + errorIfDown + ")");

        try {
            PKISocketFactory socketFactory;
            if (mAuthInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
                socketFactory = new PKISocketFactory(mAuthInfo.getClientCertNickname());
            } else {
                socketFactory = new PKISocketFactory(mConnInfo.getSecure());
            }
            socketFactory.init(config);

            mMasterConn = new LdapBoundConnection(socketFactory, mConnInfo, mAuthInfo);
            mMasterConn.connectionFactory = this;

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
            PKISocketFactory socketFactory;
            if (mAuthInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
                socketFactory = new PKISocketFactory(mAuthInfo.getClientCertNickname());
            } else {
                socketFactory = new PKISocketFactory(mConnInfo.getSecure());
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
        if (mMasterConn == null || mMasterConn.isConnected() == false)
            return;
        int increment;

        if (mNumConns < mMinConns && mTotal <= mMaxConns) {
            increment = Math.min(mMinConns - mNumConns, mMaxConns - mTotal);
            logger.debug("LdapBoundConnFactory: increasing minimum connections by " + increment);

            for (int i = increment - 1; i >= 0; i--) {

                if (doCloning == true) {
                    mConns[i] = (LdapBoundConnection) mMasterConn.clone();
                } else {
                    mConns[i] = makeNewConnection(true);
                }

            }

            mTotal += increment;
            mNumConns += increment;

            logger.debug("LdapBoundConnFactory: total connections: " + mTotal);
            logger.debug("LdapBoundConnFactory: number of connections: " + mNumConns);
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
    public synchronized LdapBoundConnection getConn(boolean waitForConn)
            throws ELdapException {
        boolean waited = false;

        logger.debug("LdapBoundConnFactory: getting a connection");

        if (mMasterConn != null)
            logger.debug("LdapBoundConnFactory: master connection is connected: " + mMasterConn.isConnected());
        else
            logger.debug("LdapBoundConnFactory: master connection is null");

        if (mMasterConn == null || !mMasterConn.isConnected()) {
            try {
                makeConnection(true);
            } catch (ELdapException e) {
                mMasterConn = null;
                logger.error("LdapBoundConnFactory: Unable to create master connection: " + e.getMessage(), e);
                throw e;
            }
        }

        if (mNumConns == 0)
            makeMinimum();

        if (mNumConns == 0) {
            if (!waitForConn)
                return null;
            try {
                logger.warn("LdapBoundConnFactory: out of LDAP connections");
                waited = true;
                while (mNumConns == 0)
                    wait();
            } catch (InterruptedException e) {
            }
        }
        mNumConns--;
        LdapBoundConnection conn = mConns[mNumConns];

        boolean isConnected = false;
        if (conn != null) {
            isConnected = conn.isConnected();
        }

        logger.debug("LdapBoundConnFactory: connection already connected: " + isConnected);

        //If masterConn is still alive, lets try to bring this one
        //back to life

        if ((isConnected == false) && (mMasterConn != null)
                && (mMasterConn.isConnected() == true)) {
            logger.debug("LdapBoundConnFactory: reestablishing connection");

            if (doCloning == true) {
                mConns[mNumConns] = (LdapBoundConnection) mMasterConn.clone();
            } else {
                try {
                    mConns[mNumConns] = makeNewConnection(true);
                } catch (ELdapException e) {
                    mConns[mNumConns] = null;
                }
            }
            conn = mConns[mNumConns];

            logger.debug("LdapBoundConnFactory: connection reestablished");
        }

        mConns[mNumConns] = null;

        if (waited) {
            logger.warn("LdapBoundConnFactory: connections are available for " + mConnInfo.getHost() + ":" + mConnInfo.getPort());
        }
        logger.debug("LdapBoundConnFactory: number of connections: " + mNumConns);

        try {
            // Before returning the connection, set the SIZELIMIT option; this
            // ensures that if the connection is recycled and the previous owner
            // changed the SIZELIMIT option to a different value, the next owner
            // always starts with the default.
            conn.setOption(LDAPv2.SIZELIMIT, mMaxResults);
        } catch (LDAPException e) {
            throw new ELdapException("Unable to set LDAP size limit: " + e.getMessage(), e);
        }

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
        LdapBoundConnection boundconn = null;

        if (conn instanceof LdapBoundConnection) {
            boundconn = (LdapBoundConnection) conn;
        } else {
            logger.warn("LdapBoundConnFactory: Unable to return connection: not a bound connection");
            return;
        }

        if (boundconn.connectionFactory != this) {
            logger.warn("LdapBoundConnFactory: Unknown connection");
        }

        for (int i = 0; i < mNumConns; i++) {
            if (mConns[i] == conn) {
                logger.warn("LdapBoundConnFactory: Connection already returned");
            }
        }

        mConns[mNumConns++] = boundconn;
        logger.debug("LdapBoundConnFactory: number of connections: " + mNumConns);

        notify();
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

    public IPasswordStore getPasswordStore() {
        return passwordStore;
    }

    public void setPasswordStore(IPasswordStore passwordStore) {
        this.passwordStore = passwordStore;
    }
}

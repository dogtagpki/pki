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

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSocketFactory;
import netscape.ldap.LDAPv2;

/**
 * Factory for getting LDAP Connections to a LDAP server
 * each connection is a seperate thread that can be bound to a different
 * authentication dn and password.
 */
public class LdapAnonConnFactory implements ILdapConnFactory {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapAnonConnFactory.class);

    protected String id;

    IConfigStore config;

    protected int mMinConns = 5;
    protected int mMaxConns = 1000;
    protected int mMaxResults = 0;
    protected LdapConnInfo mConnInfo = null;

    public static final String PROP_MINCONNS = "minConns";
    public static final String PROP_MAXCONNS = "maxConns";
    public static final String PROP_MAXRESULTS = "maxResults";
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
    public LdapAnonConnFactory(String id) {
        logger.debug("Creating LdapAnonConnFactory(" + id + ")");
        this.id = id;
    }

    public LdapAnonConnFactory(String id, boolean defErrorIfDown) {

        logger.debug("Creating LdapAnonConnFactory(" + id + ")");

        this.id = id;
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
    public LdapAnonConnFactory(
            String id,
            int minConns,
            int maxConns,
            LdapConnInfo connInfo
            ) throws ELdapException {

        logger.debug("Creating LdapAnonConnFactory(" + id + ")");

        this.id = id;

        this.mMinConns = minConns;
        this.mMaxConns = maxConns;
        this.mConnInfo = connInfo;
    }

    /**
     * Constructor for LdapAnonConnFactory
     *
     * @param minConns minimum number of connections to have available
     * @param maxConns max number of connections to have available. This is
     *            the maximum number of clones of this connection one wants to allow.
     * @param maxResults max number of results to return per query
     * @param serverInfo server connection info - host, port, etc.
     */
    public LdapAnonConnFactory(
            String id,
            int minConns,
            int maxConns,
            int maxResults,
            LdapConnInfo connInfo
            ) throws ELdapException {

        logger.debug("Creating LdapAnonConnFactory(" + id + ")");

        this.id = id;

        this.mMinConns = minConns;
        this.mMaxConns = maxConns;
        this.mMaxResults = maxResults;
        this.mConnInfo = connInfo;
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

    public void init(IConfigStore config) throws ELdapException {

        logger.debug("LdapAnonConnFactory: initialization");

        this.config = config;

        init();
    }

    public void init(IConfigStore config, IConfigStore dbConfig) throws EBaseException, ELdapException {

        logger.debug("LdapAnonConnFactory: initialization");

        this.config = config;

        this.mMinConns = dbConfig.getInteger(PROP_MINCONNS, mMinConns);
        this.mMaxConns = dbConfig.getInteger(PROP_MAXCONNS, mMaxConns);
        this.mMaxResults = dbConfig.getInteger(PROP_MAXRESULTS, mMaxResults);

        this.mConnInfo = new LdapConnInfo(dbConfig.getSubStore(PROP_LDAPCONNINFO));

        mErrorIfDown = dbConfig.getBoolean(PROP_ERROR_IF_DOWN, mDefErrorIfDown);

        init();
    }

    /**
     * initialize routine from parameters.
     */
    protected void init() throws ELdapException {
        if (mInited)
            return; // XXX should throw exception here ?

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

        mConns = new AnonConnection[mMaxConns];

        logger.debug("LdapAnonConnFactory: mininum: " + mMinConns);
        logger.debug("LdapAnonConnFactory: maximum: " + mMaxConns);
        logger.debug("LdapAnonConnFactory: host: " + mConnInfo.getHost());
        logger.debug("LdapAnonConnFactory: port: " + mConnInfo.getPort());
        logger.debug("LdapAnonConnFactory: secure: " + mConnInfo.getSecure());

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
                logger.debug("LdapAnonConnFactory: increasing minimum connections by " + increment);

                PKISocketFactory socketFactory = new PKISocketFactory(mConnInfo.getSecure());
                socketFactory.init(config);

                for (int i = increment - 1; i >= 0; i--) {
                    mConns[i] = new AnonConnection(socketFactory, mConnInfo);
                }

                mTotal += increment;
                mNumConns += increment;

                logger.debug("LdapAnonConnFactory: total connections: " + mTotal);
                logger.debug("LdapAnonConnFactory: number of connections: " + mNumConns);
            }
        } catch (LDAPException e) {
            // XXX errorCodeToString() used here so users won't see message.
            // though why are messages from exceptions being displayed to
            // users ?
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                String message = "LDAP server is unavailable: " + mConnInfo.getHost() + ":" + mConnInfo.getPort();
                logger.error("LdapAnonConnFactory: " + message, e);
                if (errorIfDown) {
                    throw new ELdapServerDownException(message, e);
                }
            } else {
                String errmsg = e.errorCodeToString();
                if (errmsg == null)
                    errmsg = e.getMessage();

                String message = "Unable to connect to LDAP server: " + errmsg;
                logger.error("LdapAnonConnFactory: " + message, e);

                throw new ELdapException(message, e);
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

        logger.debug("LdapAnonConnFactory: getting a connection");

        if (mNumConns == 0)
            makeMinimum(true);

        if (mNumConns == 0) {
            if (!waitForConn)
                return null;
            try {
                logger.warn("LdapAnonConnFactory: out of LDAP connections");
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
            logger.warn("LdapAnonConnFactory: connections are available for " + mConnInfo.getHost() + ":" + mConnInfo.getPort());
        }
        logger.debug("LdapAnonConnFactory: number of connections: " + mNumConns);

        //Beginning of fix for Bugzilla #630176
        boolean isConnected = false;
        if (conn != null) {
            isConnected = conn.isConnected();
        }

        if (!isConnected) {
            logger.debug("LdapAnonConnFactory: reestablishing connection");

            conn = null;
            try {
                PKISocketFactory socketFactory = new PKISocketFactory(mConnInfo.getSecure());
                socketFactory.init(config);

                conn = new AnonConnection(socketFactory, mConnInfo);

            } catch (LDAPException e) {
                String message = "Unable to reestablish LDAP connection: " + e.getMessage();
                logger.error("LdapAnonConnFactory: " + message, e);

                throw new ELdapException(message, e);
            }
        }
        //This is the end of the fix for Bugzilla #630176

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
            logger.warn("LdapAnonConnFactory: Unable to return connection: not an anonymous connection");
            return;
        }

        if (anon.getFacId() != mConns) {
            logger.warn("LdapAnonConnFactory: Unknown connection");
        }

        for (int i = 0; i < mNumConns; i++) {
            if (mConns[i] == anon) {
                logger.warn("LdapAnonConnFactory: Connection already returned");
            }
        }

        // this returned connection might authenticate as someone other than
        // anonymonus. Reset it to anonymous first before it returns
        // to the pool.  Do this by calling connect() again on this connection
        // to avoid doing an explicit anonymous bind
        try {
            anon.connect(mConnInfo.getHost(), mConnInfo.getPort());
        } catch (LDAPException e) {
            logger.warn("LdapAnonConnFactory: Unable to reauthenticate as anonymous");
        }

        // return the connection even if can't reauthentication anon.
        // most likely server was down.
        mConns[mNumConns++] = anon;
        logger.debug("LdapAnonConnFactory: number of connections: " + mNumConns);

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
        logger.debug("Destroying LdapAnonConnFactory(" + id + ")");
        if (mNumConns == mTotal) {
            for (int i = 0; i < mNumConns; i++) {
                try {
                    mConns[i].disconnect();
                } catch (LDAPException e) {
                    logger.warn("LdapAnonConnFactory: Unable to disconnect: " + e.getMessage(), e);
                }
                mConns[i] = null;
            }
            mTotal = 0;
            mNumConns = 0;
        } else {
            String message = "Unable to reset LDAP connection factory due to outstanding connections";
            logger.error("LdapAnonConnFactory: " + message);
            throw new ELdapException(message);
        }
    }

    /**
     * used to keep track of connections from this factory.
     */
    public class AnonConnection extends LdapAnonConnection {
        /**
         *
         */
        private static final long serialVersionUID = 4813780131074412404L;

        public AnonConnection(
                LDAPSocketFactory socketFactory,
                LdapConnInfo connInfo)
                throws LDAPException {
            super(socketFactory, connInfo);
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

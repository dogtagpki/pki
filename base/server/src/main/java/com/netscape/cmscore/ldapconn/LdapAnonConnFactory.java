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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.ldap.LdapConnFactory;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPv3;

/**
 * Factory for getting LDAP Connections to a LDAP server
 * each connection is a seperate thread that can be bound to a different
 * authentication dn and password.
 */
public class LdapAnonConnFactory extends LdapConnFactory {

    List<LdapAnonConnection> mConns;
    boolean mInited;

    /**
     * Constructor for initializing from the config store.
     * must be followed by init(ConfigStore)
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
     * @param connInfo server connection info - host, port, etc.
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
     * @param connInfo server connection info - host, port, etc.
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

    public void init(LDAPConfig dbConfig) throws EBaseException, ELdapException {

        logger.debug("LdapAnonConnFactory: initialization");

        this.mMinConns = dbConfig.getInteger(PROP_MINCONNS, mMinConns);
        this.mMaxConns = dbConfig.getInteger(PROP_MAXCONNS, mMaxConns);
        this.mMaxResults = dbConfig.getInteger(PROP_MAXRESULTS, mMaxResults);

        this.mConnInfo = new LdapConnInfo(dbConfig.getConnectionConfig());

        mErrorIfDown = dbConfig.getBoolean(PROP_ERROR_IF_DOWN, mDefErrorIfDown);

        init();
    }

    /**
     * initialize routine from parameters.
     */
    public void init() throws ELdapException {
        if (mInited)
            return; // XXX should throw exception here ?

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

        mConns = new ArrayList<>(Arrays.asList(new LdapAnonConnection[mMaxConns]));

        logger.debug("LdapAnonConnFactory: mininum: " + mMinConns);
        logger.debug("LdapAnonConnFactory: maximum: " + mMaxConns);
        logger.debug("LdapAnonConnFactory: host: " + mConnInfo.getHost());
        logger.debug("LdapAnonConnFactory: port: " + mConnInfo.getPort());
        logger.debug("LdapAnonConnFactory: secure: " + mConnInfo.getSecure());

        // initalize minimum number of connection handles available.
        if (mMinConns > 0) {
            makeMinimum(mErrorIfDown);
        }
        mInited = true;
    }

    /**
     * make the mininum configured connections
     */
    protected void makeMinimum(boolean errorIfDown) throws ELdapException {
        int realMin = Math.max(mMinConns, 1);
        try {
            if (mNumConns < realMin && mTotal < mMaxConns) {
                int increment = Math.min(realMin - mNumConns, mMaxConns - mTotal);
                logger.debug("LdapAnonConnFactory: increasing minimum connections by " + increment);

                for (int i = increment - 1; i >= 0; i--) {
                    mConns.set(i, new LdapAnonConnection(socketFactory, mConnInfo));
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
        LdapAnonConnection conn = null;
        String method = "LdapAnonConnFactory (" + id + ").getConn: ";
        logger.debug(method + "initial values. Total: " + mTotal + ", pool: " + mNumConns);

        logger.debug("LdapAnonConnFactory: getting a connection");
        if (mNumConns == 0) {
            makeMinimum(true);
        }

        while (mNumConns == 0) {
            logger.warn("LdapAnonConnFactory: waiting connections for " + mConnInfo.getHost() + ":" + mConnInfo.getPort());
            if (!waitForConn) {
                logger.warn("LdapAnonConnFactory: out of LDAP connections");
                return null;
            }
            try {
                wait();
            } catch (InterruptedException e) {
                logger.warn("LdapAnonConnFactory: connection wait interrupted");
                return null;
            }
            if (mMinConns == 0) {
                makeMinimum(true);
            }
        }

        mNumConns--;
        conn = mConns.get(mNumConns);

        mConns.set(mNumConns, null);
        logger.debug("LdapAnonConnFactory: number of connections: " + mNumConns);


        if (conn == null || !conn.isConnected()) {
            logger.debug("LdapAnonConnFactory: reestablishing connection");

            conn = null;
            try {
                conn = new LdapAnonConnection(socketFactory, mConnInfo);

            } catch (LDAPException e) {
                mTotal--;
                String message = "Unable to reestablish LDAP connection: " + e.getMessage();
                logger.error("LdapAnonConnFactory: " + message, e);
                throw new ELdapException(message, e);
            }
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
    @Override
    public synchronized void returnConn(LDAPConnection conn) {
        String method = "LdapAnonConnFactory (" + id + ").returnConn: ";
        logger.debug(method + "initial values. Total: " + mTotal + ", pool: " + mNumConns);

        if (conn == null) {
            return;
        }
        LdapAnonConnection anon = null;

        // check if conn is valid and from this factory.
        if (conn instanceof LdapAnonConnection) {
            anon = (LdapAnonConnection) conn;
        } else {
            logger.warn("LdapAnonConnFactory: Unable to return connection: not an anonymous connection");
            return;
        }

        if (mConns.contains(anon)) {
            logger.warn("LdapAnonConnFactory: Connection already returned");
            --mTotal;
            notifyAll();
            return;
        }

        if(mNumConns < mMinConns) {
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
            mConns.set(mNumConns++, anon);
        } else {
            try {
                anon.disconnect();
            } catch (LDAPException e) {
                logger.warn("LdapAnonConnFactory: Unable to disconnect: " + e.getMessage(), e);
            }
            --mTotal;
        }
        logger.debug("LdapAnonConnFactory: number of connections: " + mNumConns);

        notifyAll();
        logger.debug(method + " final values. Total: " + mTotal + ", pool: " + mNumConns);
    }

    /**
     * resets this factory - if no connections outstanding,
     * disconnections all connections and resets everything to 0 as if
     * no connections were ever made. intended to be called just before
     * shutdown or exit to disconnection and cleanup connections.
     */
    // ok only if no connections outstanding.
    @Override
    public synchronized void reset()
            throws ELdapException {
        logger.debug("Destroying LdapAnonConnFactory(" + id + ")");
        if (mNumConns == mTotal) {
            for (int i = 0; i < mNumConns; i++) {
                try {
                    mConns.get(i).disconnect();
                } catch (LDAPException e) {
                    logger.warn("LdapAnonConnFactory: Unable to disconnect: " + e.getMessage(), e);
                }
                mConns.set(i, null);
            }
            mTotal = 0;
            mNumConns = 0;
            mConns = new ArrayList<>(Arrays.asList(new LdapAnonConnection[mMaxConns]));
        } else {
            String message = "Unable to reset LDAP connection factory due to outstanding connections";
            logger.error("LdapAnonConnFactory: " + message);
            throw new ELdapException(message);
        }
    }
}

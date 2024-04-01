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
package com.netscape.certsrv.ldap;

import com.netscape.cmscore.ldapconn.LdapConnInfo;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPSocketFactory;

/**
 * Maintains a pool of connections to the LDAP server.
 * Multiple threads use this interface to utilize and release
 * the Ldap connection resources.
 */
public abstract class LdapConnFactory {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapConnFactory.class);

    public static final String PROP_MINCONNS = "minConns";
    public static final String PROP_MAXCONNS = "maxConns";
    public static final String PROP_MAXRESULTS = "maxResults";
    public static final String PROP_ERROR_IF_DOWN = "errorIfDown";

    protected String id;

    protected LDAPSocketFactory socketFactory;
    protected LdapConnInfo mConnInfo;

    protected int mMinConns = 5;
    protected int mMaxConns = 1000;
    protected int mMaxResults = 0;

    /**
     * number of available conns in array
     */
    protected int mNumConns = 0;

    /**
     * total num conns
     */
    protected int mTotal = 0;

    /**
     * return error if server is down at creation time.
     */
    protected boolean mErrorIfDown;

    /**
     * default value for the above at init time.
     */
    protected boolean mDefErrorIfDown;

    public LDAPSocketFactory getSocketFactory() {
        return socketFactory;
    }

    public void setSocketFactory(LDAPSocketFactory socketFactory) {
        this.socketFactory = socketFactory;
    }

    /**
     * returns connection info.
     */
    public LdapConnInfo getConnInfo() {
        return mConnInfo;
    }

    /**
     *
     * Used for disconnecting all connections.
     * Used just before a subsystem
     * shutdown or process exit.
     *
     * @exception EldapException on Ldap failure when closing connections.
     */
    public abstract void reset() throws ELdapException;

    /**
     * Returns the number of free connections available from this pool.
     *
     * @return Integer number of free connections.
     */
    public synchronized int freeConn() {
        return mNumConns;
    }

    /**
     * Returns the number of total connections available from this pool.
     * Includes sum of free and in use connections.
     *
     * @return Integer number of total connections.
     */
    public int totalConn() {
        return mTotal;
    }

    /**
     * Returns the maximum number of connections available from this pool.
     *
     * @return Integer maximum number of connections.
     */
    public int maxConn() {
        return mMaxConns;
    }

    /**
     * Request access to a Ldap connection from the pool.
     *
     * @exception ELdapException if any error occurs, such as a
     * @return Ldap connection object.
     *         connection is not available
     */
    public abstract LDAPConnection getConn() throws ELdapException;

    /**
     * Return connection to the factory. mandatory after a getConn().
     *
     * @param conn Ldap connection object to be returned to the free list of the pool.
     * @exception ELdapException On any failure to return the connection.
     */
    public abstract void returnConn(LDAPConnection conn) throws ELdapException;

    @Override
    protected void finalize() throws Exception {
        reset();
    }
}

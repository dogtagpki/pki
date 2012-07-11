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
package com.netscape.cmscore.connector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.connector.IHttpConnection;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmsutil.http.JssSSLSocketFactory;
import com.netscape.cmsutil.net.ISocketFactory;

/**
 * Factory for getting HTTP Connections to a HTTPO server
 */
public class HttpConnFactory {
    protected int mMinConns = 1;
    protected int mMaxConns = 30;

    private ILogger mLogger = CMS.getLogger();

    private int mNumConns = 0; // number of available conns in array
    private int mTotal = 0; // total num conns
    private IHttpConnection mConns[];
    @SuppressWarnings("unused")
    private IAuthority mSource;
    private IRemoteAuthority mDest = null;
    private String mNickname = "";
    private int mTimeout = 0;

    /**
     * Constructor for initializing from the config store.
     * must be followed by init(IConfigStore)
     */
    public HttpConnFactory() {
    }

    /**
     * Constructor for HttpConnFactory
     *
     * @param minConns minimum number of connections to have available
     * @param maxConns max number of connections to have available. This is
     * @param serverInfo server connection info - host, port, etc.
     */
    public HttpConnFactory(int minConns, int maxConns, IAuthority source, IRemoteAuthority dest, String nickname,
            int timeout) throws EBaseException {

        CMS.debug("In HttpConnFactory constructor mTimeout " + timeout);
        mSource = source;
        mDest = dest;
        mNickname = nickname;
        mTimeout = timeout;

        init(minConns, maxConns);
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
    private void init(int minConns, int maxConns
            )
                    throws EBaseException {

        CMS.debug("min conns " + minConns + " maxConns " + maxConns);
        if (minConns <= 0 || maxConns <= 0 || minConns > maxConns) {
            CMS.debug("bad values from CMS.cfg");

        } else {

            mMinConns = minConns;
            mMaxConns = maxConns;
        }

        CMS.debug("before creating httpconn array");

        mConns = new IHttpConnection[mMaxConns];

        // Create connection handle and make initial connection

        CMS.debug("before makeConnection");

        CMS.debug(
                "initializing HttpConnFactory with mininum " + mMinConns + " and maximum " + mMaxConns +
                        " connections to ");

        // initalize minimum number of connection handles available.
        //makeMinimum();

        CMS.debug("leaving HttpConnFactory init.");
    }

    private IHttpConnection createConnection() throws EBaseException {

        IHttpConnection retConn = null;

        CMS.debug("In HttpConnFactory.createConnection.");

        try {
            ISocketFactory tFactory = new JssSSLSocketFactory(mNickname);

            if (mTimeout == 0) {
                retConn = CMS.getHttpConnection(mDest, tFactory);
            } else {
                retConn = CMS.getHttpConnection(mDest, tFactory, mTimeout);
            }

        } catch (Exception e) {

            CMS.debug("can't make new Htpp Connection");

            throw new EBaseException(
                    "Can't create new Http Connection");
        }

        return retConn;
    }

    /**
     * makes the minumum number of connections
     */
    private void makeMinimum() throws EBaseException {

        CMS.debug("In HttpConnFactory.makeMinimum.");
        int increment;

        if (mNumConns < mMinConns && mTotal <= mMaxConns) {

            increment = Math.min(mMinConns - mNumConns, mMaxConns - mTotal);

            if (increment == 0)
                return;

            CMS.debug(
                    "increasing minimum connections by " + increment);
            for (int i = increment - 1; i >= 0; i--) {
                mConns[i] = createConnection();
            }
            mTotal += increment;
            mNumConns += increment;
            CMS.debug("new total available http connections " + mTotal);
            CMS.debug("new number of http connections " + mNumConns);
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
     * IHttpConnection c = null;
     * try {
     *     c = factory.getConn();
     *     myclass.do_something_with_c(c);
     * } catch (EBaseException e) {
     *     handle_error_here();
     * } finally {
     *     factory.returnConn(c);
     * }
     * </pre>
     */
    public IHttpConnection getConn()
            throws EBaseException {
        return getConn(true);
    }

    /**
     * Returns a Http connection - a clone of the master connection.
     * All connections should be returned to the factory using returnConn()
     * to recycle connection objects.
     * If not returned the limited max number is affected but if that
     * number is large not much harm is done.
     * Returns null if maximum number of connections reached.
     * The best thing to do is to put returnConn in a finally clause so it
     * always gets called. For example,
     *
     * <pre>
     * IHttpConnnection c = null;
     * try {
     *     c = factory.getConn();
     *     myclass.do_something_with_c(c);
     * } catch (EBaseException e) {
     *     handle_error_here();
     * } finally {
     *     factory.returnConn(c);
     * }
     * </pre>
     */
    public synchronized IHttpConnection getConn(boolean waitForConn)
            throws EBaseException {
        boolean waited = false;

        CMS.debug("In HttpConnFactory.getConn");
        if (mNumConns == 0)
            makeMinimum();
        if (mNumConns == 0) {
            if (!waitForConn)
                return null;
            try {
                CMS.debug("getConn: out of http connections");
                log(ILogger.LL_WARN,
                        "Ran out of http connections available ");
                waited = true;
                CMS.debug("HttpConn:about to wait for a new http connection");
                while (mNumConns == 0)
                    wait();

                CMS.debug("HttpConn:done waiting for new http connection");
            } catch (InterruptedException e) {
            }
        }
        mNumConns--;
        IHttpConnection conn = mConns[mNumConns];

        mConns[mNumConns] = null;

        if (waited) {
            CMS.debug("HttpConn:had to wait for an available connection from pool");
            log(ILogger.LL_WARN,
                    "Http connections are available again in http connection pool ");
        }
        CMS.debug("HttpgetConn: mNumConns now " + mNumConns);

        return conn;
    }

    /**
     * Teturn connection to the factory.
     * This is mandatory after a getConn().
     * The best thing to do is to put returnConn in a finally clause so it
     * always gets called. For example,
     *
     * <pre>
     * IHttpConnection c = null;
     * try {
     *     c = factory.getConn();
     *     myclass.do_something_with_c(c);
     * } catch (EBaseException e) {
     *     handle_error_here();
     * } finally {
     *     factory.returnConn(c);
     * }
     * </pre>
     */
    public synchronized void returnConn(IHttpConnection conn) {

        CMS.debug("In HttpConnFactory.returnConn");
        if (conn == null) {
            return;
        }
        IHttpConnection boundconn = conn;

        for (int i = 0; i < mNumConns; i++) {
            if (mConns[i] == conn) {
                CMS.debug(
                        "returnConn: previously returned connection. " + conn);

            }
        }
        mConns[mNumConns++] = boundconn;
        CMS.debug("HttpreturnConn: mNumConns now " + mNumConns);
        notify();
    }

    /**
     * handy routine for logging in this class.
     */
    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
                "In Http (bound) connection pool to" +
                        msg);
    }
}
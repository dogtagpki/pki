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

import org.dogtagpki.server.PKIClientSocketListener;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.connector.IHttpConnection;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.logging.Logger;
import com.netscape.cmsutil.http.JssSSLSocketFactory;
import com.netscape.cmsutil.net.ISocketFactory;

/**
 * Factory for getting HTTP Connections to a HTTPO server
 */
public class HttpConnFactory {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(HttpConnFactory.class);

    protected int mMinConns = 1;
    protected int mMaxConns = 30;

    private Logger mLogger = Logger.getLogger();

    private int mNumConns = 0; // number of available conns in array
    private int mTotal = 0; // total num conns
    private IHttpConnection mConns[];
    @SuppressWarnings("unused")
    private IAuthority mSource;
    private IRemoteAuthority mDest = null;
    private String mNickname = "";
    private String mClientCiphers = null;
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
    public HttpConnFactory(int minConns, int maxConns, IAuthority source, IRemoteAuthority dest, String nickname, String clientCiphers,
            int timeout) throws EBaseException {

        logger.debug("In HttpConnFactory constructor mTimeout " + timeout);
        if (mClientCiphers != null)
            logger.debug("In HttpConnFactory constructor mClientCiphers: " + mClientCiphers);
        else
            logger.debug("In HttpConnFactory constructor mClientCiphers not specified, will take default ");
        mSource = source;
        mDest = dest;
        mNickname = nickname;
        mClientCiphers = clientCiphers;
        mTimeout = timeout;

        init(minConns, maxConns);
    }

    /**
     * initialize parameters obtained from either constructor or
     * config store
     *
     * @param minConns minimum number of connection handles to have available.
     * @param maxConns maximum total number of connections to ever have.
     * @param connInfo ldap connection info.
     * @param authInfo ldap authentication info.
     * @exception ELdapException if any error occurs.
     */
    private void init(int minConns, int maxConns
            )
                    throws EBaseException {

        logger.debug("min conns " + minConns + " maxConns " + maxConns);
        if (minConns <= 0 || maxConns <= 0 || minConns > maxConns) {
            logger.warn("bad values from CMS.cfg");

        } else {

            mMinConns = minConns;
            mMaxConns = maxConns;
        }

        logger.debug("before creating httpconn array");

        mConns = new IHttpConnection[mMaxConns];

        // Create connection handle and make initial connection

        logger.debug("before makeConnection");

        logger.debug(
                "initializing HttpConnFactory with mininum " + mMinConns + " and maximum " + mMaxConns +
                        " connections to ");

        // initalize minimum number of connection handles available.
        //makeMinimum();

        logger.debug("leaving HttpConnFactory init.");
    }

    private IHttpConnection createConnection() throws EBaseException {

        IHttpConnection retConn = null;

        logger.debug("In HttpConnFactory.createConnection.");

        try {
            ISocketFactory tFactory = new JssSSLSocketFactory(mNickname, mClientCiphers);
            PKIClientSocketListener sockListener = new PKIClientSocketListener();
            JssSSLSocketFactory factory = (JssSSLSocketFactory) tFactory;
            factory.addSocketListener(sockListener);

            if (mTimeout == 0) {
                retConn = new HttpConnection(mDest, tFactory);
            } else {
                retConn = new HttpConnection(mDest, tFactory, mTimeout);
            }

        } catch (Exception e) {
            String message = "Unable to create HTTP connection: " + e.getMessage();
            logger.error(message, e);
            throw new EBaseException(message, e);
        }

        return retConn;
    }

    /**
     * makes the minumum number of connections
     */
    private void makeMinimum() throws EBaseException {

        logger.debug("In HttpConnFactory.makeMinimum.");
        int increment;

        if (mNumConns < mMinConns && mTotal <= mMaxConns) {

            increment = Math.min(mMinConns - mNumConns, mMaxConns - mTotal);

            if (increment == 0)
                return;

            logger.debug("increasing minimum connections by " + increment);
            for (int i = increment - 1; i >= 0; i--) {
                mConns[i] = createConnection();
            }
            mTotal += increment;
            mNumConns += increment;
            logger.debug("new total available http connections " + mTotal);
            logger.debug("new number of http connections " + mNumConns);
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

        logger.debug("In HttpConnFactory.getConn");
        if (mNumConns == 0)
            makeMinimum();
        if (mNumConns == 0) {
            if (!waitForConn)
                return null;
            try {
                logger.debug("getConn: out of http connections");
                log(ILogger.LL_WARN,
                        "Ran out of http connections available ");
                waited = true;
                logger.debug("HttpConn:about to wait for a new http connection");
                while (mNumConns == 0)
                    wait();

                logger.debug("HttpConn:done waiting for new http connection");
            } catch (InterruptedException e) {
            }
        }
        mNumConns--;
        IHttpConnection conn = mConns[mNumConns];

        mConns[mNumConns] = null;

        if (waited) {
            logger.warn("HttpConn:had to wait for an available connection from pool");
            log(ILogger.LL_WARN,
                    "Http connections are available again in http connection pool ");
        }
        logger.debug("HttpgetConn: mNumConns now " + mNumConns);

        return conn;
    }

    /**
     * Return connection to the factory.
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

        logger.debug("In HttpConnFactory.returnConn");
        if (conn == null) {
            return;
        }
        IHttpConnection boundconn = conn;

        for (int i = 0; i < mNumConns; i++) {
            if (mConns[i] == conn) {
                logger.debug("returnConn: previously returned connection. " + conn);

            }
        }
        mConns[mNumConns++] = boundconn;
        logger.debug("HttpreturnConn: mNumConns now " + mNumConns);
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

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

import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.connector.IHttpConnection;
import com.netscape.certsrv.connector.IHttpPKIMessage;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IResender;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmsutil.http.HttpResponse;
import com.netscape.cmsutil.http.JssSSLSocketFactory;
import com.netscape.cmsutil.net.ISocketFactory;

import org.dogtagpki.server.PKIClientSocketListener;

public class HttpConnector implements IConnector {
    protected IAuthority mSource = null;
    protected IRemoteAuthority mDest = null;
    protected ISocketFactory mFactory = null;

    // XXX todo make this a pool.
    // XXX use CMMF in the future.
    protected IHttpConnection mConn = null;
    private IResender mResender = null;
    @SuppressWarnings("unused")
    private int mTimeout;

    private HttpConnFactory mConnFactory = null;

    public HttpConnector(IAuthority source, String nickName, String clientCiphers,
            IRemoteAuthority dest, int resendInterval, IConfigStore config) throws EBaseException {

        mTimeout = 0;
        mSource = source;
        mDest = dest;
        PKIClientSocketListener sockListener = new PKIClientSocketListener();
        mFactory = new JssSSLSocketFactory(nickName, clientCiphers);

        JssSSLSocketFactory factory = (JssSSLSocketFactory)mFactory;
        factory.addSocketListener(sockListener);

        int minConns = config.getInteger("minHttpConns", 1);
        int maxConns = config.getInteger("maxHttpConns", 15);

        CMS.debug("HttpConn: min " + minConns);
        CMS.debug("HttpConn: max " + maxConns);

        try {
            mConnFactory = new HttpConnFactory(minConns, maxConns, source, dest, nickName, clientCiphers, 0);
        } catch (EBaseException e) {
            CMS.debug("can't create new HttpConnFactory " + e.toString());
        }

        //        mConn = CMS.getHttpConnection(dest, mFactory);
        // this will start resending past requests in parallel.
        if (resendInterval >= 0) {
            mResender = CMS.getResender(mSource, nickName, clientCiphers, dest, resendInterval);
        }
    }

    // Inserted by beomsuk
    public HttpConnector(IAuthority source, String nickName, String clientCiphers,
            IRemoteAuthority dest, int resendInterval, IConfigStore config, int timeout) throws EBaseException {
        mSource = source;
        mDest = dest;
        mTimeout = timeout;
        PKIClientSocketListener sockListener = new PKIClientSocketListener();
        mFactory = new JssSSLSocketFactory(nickName, clientCiphers);

        JssSSLSocketFactory factory = (JssSSLSocketFactory) mFactory;
        factory.addSocketListener(sockListener);

        int minConns = config.getInteger("minHttpConns", 1);
        int maxConns = config.getInteger("maxHttpConns", 15);

        CMS.debug("HttpConn: min " + minConns);
        CMS.debug("HttpConn: max " + maxConns);

        try {
            mConnFactory = new HttpConnFactory(minConns, maxConns, source, dest, nickName, clientCiphers, timeout);
        } catch (EBaseException e) {
            CMS.debug("can't create new HttpConnFactory");
        }

        // this will start resending past requests in parallel.
        if (resendInterval >= 0) {
            mResender = CMS.getResender(mSource, nickName, clientCiphers, dest, resendInterval);
        }
    }

    // Insert end

    // cfu
    public HttpResponse send(String op, String msg)
        throws EBaseException {
        CMS.debug("HttpConnector: send(): begins");
        HttpResponse resp = null;
        IHttpConnection curConn = null;
        String uri;

        if (op != null) {
            uri = mDest.getURI(op);
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "HttpConnector.send(): op null"));
        }
        if (uri == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "HttpConnector.send(): cannot find uri for op"));
        }

        try {
            curConn = mConnFactory.getConn();
            curConn.setRequestURI(uri);
            resp = curConn.send(msg);
        } catch (EBaseException e) {
            CMS.debug("HttpConnector: send():"+ e.toString());
        } finally {
            if (curConn != null) {
                mConnFactory.returnConn(curConn);
            }
        }
        return resp;
    }

    public boolean send(IRequest r)
            throws EBaseException {
        IHttpConnection curConn = null;

        try {
            IHttpPKIMessage tomsg = (IHttpPKIMessage) CMS.getHttpPKIMessage();
            HttpPKIMessage replymsg = null;

            tomsg.fromRequest(r);
            CMS.debug("Before synch");

            curConn = mConnFactory.getConn();

            CMS.debug("HttpConnector.send " + curConn);

            replymsg = (HttpPKIMessage) curConn.send(tomsg);

            if (replymsg == null) {
                CMS.debug("HttpConncter. replymsg is null");
                return false;
            }

            CMS.debug("HttpConncter.send has been called");

            RequestStatus replyStatus;
            RequestId replyRequestId;

            replyStatus = RequestStatus.fromString(replymsg.reqStatus);
            int index = replymsg.reqId.lastIndexOf(':');

            replyRequestId = new RequestId(replymsg.reqId.substring(index + 1));
            CMS.debug("reply request id " + replyRequestId);
            r.setExtData(IRequest.REMOTE_REQID, replyRequestId.toString());

            CMS.debug("reply request type " + r.getRequestType());
            CMS.debug("reply status " + replyStatus);

            // non terminal states.
            // XXX hack: don't resend get revocation info requests since
            // resent results are ignored.
            if ((!r.getRequestType().equals(
                        IRequest.GETREVOCATIONINFO_REQUEST)) &&
                    (replyStatus == RequestStatus.BEGIN ||
                            replyStatus == RequestStatus.PENDING ||
                            replyStatus == RequestStatus.SVC_PENDING ||
                    replyStatus == RequestStatus.APPROVED)) {
                CMS.debug("HttpConn:  remote request id still pending " +
                        r.getRequestId() + " state " + replyStatus);
                /*
                mSource.log(ILogger.LL_INFO,
                        CMS.getLogMessage("CMSCORE_CONNECTOR_REQUEST_NOT_COMPLETED", r.getRequestId().toString()));
                */
                if (mResender != null)
                    mResender.addRequest(r);
                return false;
            }

            // request was completed.
            replymsg.toRequest(r); // this only copies contents.

            // terminal states other than completed
            if (replyStatus == RequestStatus.REJECTED ||
                    replyStatus == RequestStatus.CANCELED) {
                CMS.debug(
                        "remote request id " + r.getRequestId() +
                                " was rejected or cancelled.");
                r.setExtData(IRequest.REMOTE_STATUS, replyStatus.toString());
                r.setExtData(IRequest.RESULT, IRequest.RES_ERROR);
                r.setExtData(IRequest.ERROR,
                        new EBaseException(CMS.getUserMessage("CMS_BASE_REMOTE_AUTHORITY_ERROR")));
                // XXX overload svcerrors for now.
                Vector<String> policyErrors = r.getExtDataInStringVector(IRequest.ERRORS);

                if (policyErrors != null && policyErrors.size() > 0) {
                    r.setExtData(IRequest.SVCERRORS, policyErrors);
                }
            }

            CMS.debug(
                    "remote request id " + r.getRequestId() + " was completed");
            return true;
        } catch (EBaseException e) {
            CMS.debug("HttpConn: inside EBaseException " + e.toString());

            if (!r.getRequestType().equals(IRequest.GETREVOCATIONINFO_REQUEST)) {
                if (mResender != null)
                    mResender.addRequest(r);
            }

            CMS.debug("HttpConn:  error sending request to cert " + e.toString());
            /*
            mSource.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CONNECTOR_SEND_REQUEST", r.getRequestId()
                    .toString(), mDest.getHost(), Integer.toString(mDest.getPort())));
            */
            // mSource.log(ILogger.LL_INFO,
            //    "Queing " + r.getRequestId() + " for resend.");
            return false;
        } finally {

            if (curConn != null) {
                mConnFactory.returnConn(curConn);
            }
        }
    }

    public void start() {
        CMS.debug("Starting HttpConnector resender thread");
        if (mResender != null)
            mResender.start("HttpConnector");
    }

    public void stop() {
        CMS.debug("Stopping HttpConnector resender thread");
        if (mResender != null)
            mResender.stop();
    }

}

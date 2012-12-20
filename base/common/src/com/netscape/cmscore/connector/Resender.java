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

import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IResender;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.http.JssSSLSocketFactory;

/**
 * Resend requests at intervals to the server to check if it's been completed.
 * Default interval is 5 minutes.
 */
public class Resender implements IResender {
    public static final int MINUTE = 60;

    protected IAuthority mAuthority = null;
    IRequestQueue mQueue = null;
    protected IRemoteAuthority mDest = null;
    ScheduledExecutorService executorService;

    /* Vector of Request Id *Strings* */
    protected Vector<String> mRequestIds = new Vector<String>();

    protected HttpConnection mConn = null;

    protected String mNickName = null;
    protected boolean connected = false;

    // default interval.
    // XXX todo add another interval for requests unsent because server
    // was down (versus being serviced in request queue)
    protected int mInterval = 1 * MINUTE;

    public Resender(IAuthority authority, String nickName, IRemoteAuthority dest) {
        mAuthority = authority;
        mQueue = mAuthority.getRequestQueue();
        mDest = dest;
        mNickName = nickName;
    }

    public Resender(
            IAuthority authority, String nickName,
            IRemoteAuthority dest, int interval) {
        mAuthority = authority;
        mQueue = mAuthority.getRequestQueue();
        mDest = dest;
        mNickName = nickName;
        if (interval > 0)
            mInterval = interval; // interval specified in seconds.
    }

    // must be done after a subsystem 'start' so queue is initialized.
    private void initRequests() {
        mQueue = mAuthority.getRequestQueue();
        // get all requests in mAuthority that are still pending.
        IRequestList list =
                mQueue.listRequestsByStatus(RequestStatus.SVC_PENDING);

        while (list != null && list.hasMoreElements()) {
            RequestId rid = list.nextRequestId();
            CMS.debug("added request Id " + rid + " in init to resend queue.");
            // note these are added as strings
            mRequestIds.addElement(rid.toString());
        }
    }

    public void addRequest(IRequest r) {
        synchronized (mRequestIds) {
            // note the request ids are added as strings.
            mRequestIds.addElement(r.getRequestId().toString());
        }
        CMS.debug("added " + r.getRequestId() + " to resend queue");
    }

    public void start(final String name) {
        CMS.debug("Starting resender thread with interval " + mInterval);

        // schedule task to run immediately and repeat after specified interval
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            public Thread newThread(Runnable r) {
                return new Thread(r, name);
            }
        });
        executorService.scheduleWithFixedDelay(this, 0, mInterval, TimeUnit.SECONDS);

    }

    public void run() {
        if (! CMS.isInRunningState())
            return;

        if (! connected) {
            CMS.debug("Connecting ...");
            mConn = new HttpConnection(mDest, new JssSSLSocketFactory(mNickName));
            initRequests();
            connected = true;
        }
        resend();
    }

    public void stop() {
        // shutdown executorService without interrupting running task
        if (executorService != null) executorService.shutdown();
    }

    private void resend() {
        // clone a seperate list so mRequestIds can be modified
        @SuppressWarnings("unchecked")
        Vector<String> rids = (Vector<String>) mRequestIds.clone();
        Vector<RequestId> completedRids = new Vector<RequestId>();

        // resend each request to CA to ping for status.
        Enumeration<String> enum1 = rids.elements();

        while (enum1.hasMoreElements()) {
            // request ids are added as strings.
            String ridString = enum1.nextElement();
            RequestId rid = new RequestId(ridString);
            IRequest r = null;

            CMS.debug(
                    "resend processing request id " + rid);

            try {
                r = mQueue.findRequest(rid);
            } catch (EBaseException e) {
                // XXX bad case. should we remove the rid now ?
                mAuthority.log(ILogger.LL_WARN,
                        CMS.getLogMessage("CMSCORE_CONNECTOR_REQUEST_NOT_FOUND", rid.toString()));
                continue;
            }
            try {
                if (r.getRequestStatus() != RequestStatus.SVC_PENDING) {
                    // request not pending anymore - aborted or cancelled.
                    completedRids.addElement(rid);
                    CMS.debug(
                            "request id " + rid + " no longer service pending");
                } else {
                    boolean completed = send(r);

                    if (completed) {
                        completedRids.addElement(rid);
                        mAuthority.log(ILogger.LL_INFO,
                                CMS.getLogMessage("CMSCORE_CONNECTOR_REQUEST_COMPLETED", rid.toString()));
                    }
                }
            } catch (IOException e) {
                mAuthority.log(ILogger.LL_WARN,
                        CMS.getLogMessage("CMSCORE_CONNECTOR_REQUEST_ERROR", rid.toString(), e.toString()));
            } catch (EBaseException e) {
                // if connection is down, don't send the remaining request
                // as it will sure fail.
                mAuthority.log(ILogger.LL_WARN, CMS.getLogMessage("CMSCORE_CONNECTOR_DOWN"));
                if (e.toString().indexOf("connection not available") >= 0)
                    break;
            }
        }

        // remove completed ones from list so they won't be resent.
        Enumeration<RequestId> en = completedRids.elements();

        synchronized (mRequestIds) {
            while (en.hasMoreElements()) {
                RequestId id = en.nextElement();

                CMS.debug(
                        "Connector: Removed request " + id + " from re-send queue");
                mRequestIds.removeElement(id.toString());
                CMS.debug(
                        "Connector: mRequestIds now has " +
                                mRequestIds.size() + " elements.");
            }
        }
    }

    // this is almost the same as connector's send.
    private boolean send(IRequest r)
            throws IOException, EBaseException {

        try {
            HttpPKIMessage tomsg = new HttpPKIMessage();
            HttpPKIMessage replymsg = null;

            tomsg.fromRequest(r);
            replymsg = (HttpPKIMessage) mConn.send(tomsg);
            if (replymsg == null)
                return false;
            CMS.debug(
                    r.getRequestId() + " resent to CA");

            RequestStatus replyStatus =
                    RequestStatus.fromString(replymsg.reqStatus);
            int index = replymsg.reqId.lastIndexOf(':');
            RequestId replyRequestId =
                    new RequestId(replymsg.reqId.substring(index + 1));

            if (Debug.ON)
                Debug.trace("reply request id " + replyRequestId +
                        " for request " + r.getRequestId());

            if (replyStatus != RequestStatus.COMPLETE) {
                CMS.debug("resend " +
                        r.getRequestId() + " still not completed.");
                return false;
            }

            // request was completed. copy relevant contents.
            replymsg.toRequest(r);
            if (Debug.ON)
                Debug.trace("resend request id was completed " + r.getRequestId());
            mQueue.markAsServiced(r);
            mQueue.releaseRequest(r);
            CMS.debug(
                    "resend released request " + r.getRequestId());
            return true;
        } catch (EBaseException e) {
            // same as not having sent it, so still want to resend.
            mAuthority.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CONNECTOR_RESEND_ERROR", r.getRequestId().toString(), e.toString()));
            if (e.toString().indexOf("Connection refused by peer") > 0)
                throw new EBaseException("connection not available");
        }
        return false;

    }

}

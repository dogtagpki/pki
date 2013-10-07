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

import java.util.Hashtable;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.util.Debug;

public class LocalConnector implements IConnector {
    ICertAuthority mSource = null;
    IAuthority mDest = null;
    Hashtable<String, IRequest> mSourceReqs = new Hashtable<String, IRequest>();

    public LocalConnector(ICertAuthority source, IAuthority dest) {
        mSource = source;
        // mSource.log(ILogger.LL_DEBUG, "Local connector setup for source " +
        //    mSource.getId());
        mDest = dest;
        CMS.debug("Local connector setup for dest " +
                mDest.getId());
        // register for events.
        mDest.registerRequestListener(new LocalConnListener());
        CMS.debug("Connector inited");
    }

    /**
     * send request to local authority.
     * returns resulting request
     */
    public boolean send(IRequest r) throws EBaseException {
        if (Debug.ON) {
            Debug.print("send request type "
                    + r.getRequestType() + " status=" + r.getRequestStatus() + " to " + mDest.getId() + " id="
                    + r.getRequestId() + "\n");
        }
        CMS.debug("send request type " + r.getRequestType() +
                " to " + mDest.getId());

        IRequestQueue destQ = mDest.getRequestQueue();
        IRequest destreq = destQ.newRequest(r.getRequestType());

        CMS.debug("local connector dest req " +
                destreq.getRequestId() + " created for source rId " + r.getRequestId());
        //  mSource.log(ILogger.LL_DEBUG,
        //     "setting connector dest " + mDest.getId() +
        //    " source id to " + r.getRequestId());

        // XXX set context to the real identity later.
        destreq.setSourceId(
                mSource.getX500Name().toString() + ":" + r.getRequestId().toString());
        //destreq.copyContents(r);  // copy meta attributes in request.
        transferRequest(r, destreq);
        // XXX requestor type is not transferred on return.
        destreq.setExtData(IRequest.REQUESTOR_TYPE,
                IRequest.REQUESTOR_RA);
        CMS.debug("connector dest " + mDest.getId() +
                " processing " + destreq.getRequestId());

        // set context before calling process request so
        // that request subsystem can record the creator
        // of the request
        SessionContext s = SessionContext.getContext();

        if (s.get(SessionContext.USER_ID) == null) {
            // use $local$ to represent it is not a user who
            // submit the request, but it is a local subsystem
            s.put(SessionContext.USER_ID, "$local$" + mSource.getId());
        }

        // Locally cache the source request so that we
        // can update it when the dest request is
        // processed (when LocalConnListener is being called).
        mSourceReqs.put(r.getRequestId().toString(), r);
        try {
            destQ.processRequest(destreq);
        } catch (EBaseException ex) {
            throw ex;
        } finally {
            // release the source id either success or failure
            mSourceReqs.remove(r.getRequestId().toString());
        }

        CMS.debug("connector dest " + mDest.getId() +
                " processed " + destreq.getRequestId() +
                " status " + destreq.getRequestStatus());

        if (destreq.getRequestStatus() == RequestStatus.COMPLETE) {
            // no need to transfer contents if request wasn't complete.
            transferRequest(destreq, r);
            return true;
        } else {
            return false;
        }
    }

    public class LocalConnListener implements IRequestListener {

        public void init(ISubsystem sys, IConfigStore config)
                throws EBaseException {
        }

        public void set(String name, String val) {
        }

        public void accept(IRequest destreq) {
            if (Debug.ON) {
                Debug.print("dest " + mDest.getId() + " done with " + destreq.getRequestId());
            }
            CMS.debug(
                    "dest " + mDest.getId() + " done with " + destreq.getRequestId());

            IRequestQueue sourceQ = mSource.getRequestQueue();
            // accept requests that only belong to us.
            // XXX review death scenarios here. - If system dies anywhere
            // here need to check all requests at next server startup.
            String sourceNameAndId = destreq.getSourceId();
            String sourceName = mSource.getX500Name().toString();

            if (sourceNameAndId == null ||
                    !sourceNameAndId.toString().regionMatches(0,
                            sourceName, 0, sourceName.length())) {
                CMS.debug("request " + destreq.getRequestId() +
                        " from " + sourceNameAndId + " not ours.");
                return;
            }
            int index = sourceNameAndId.lastIndexOf(':');

            if (index == -1) {
                mSource.log(ILogger.LL_FAILURE,
                        "request " + destreq.getRequestId() +
                                " for " + sourceNameAndId + " malformed.");
                return;
            }
            String sourceId = sourceNameAndId.substring(index + 1);
            RequestId rId = new RequestId(sourceId);

            //    mSource.log(ILogger.LL_DEBUG, mDest.getId() + " " +
            //       destreq.getRequestId() + " mapped to " + mSource.getId() + " " + rId);

            IRequest r = null;

            // 391439: Previously, we try to access the request
            // via request queue here. Due to the recent
            // performance enhancement, approved request will
            // not be immediately available in the database. So
            // retrieving the request from the queue within
            // the serviceRequest() function will have
            // diffculities.
            // You may wonder what happen if the system crashes
            // during the request servicing. Yes, the request
            // will be lost. This is ok because the users will
            // resubmit their requests again.
            // Note that the pending requests, on the other hand,
            // are persistent before the servicing.
            // Please see stateEngine() function in
            // ARequestQueue.java for details.
            r = mSourceReqs.get(rId.toString());
            if (r != null) {
                if (r.getRequestStatus() != RequestStatus.SVC_PENDING) {
                    mSource.log(ILogger.LL_FAILURE,
                            "request state of " + rId + "not pending " +
                                    " from dest authority " + mDest.getId());
                    sourceQ.releaseRequest(r);
                    return;
                }
                transferRequest(destreq, r);
                sourceQ.markAsServiced(r);
                sourceQ.releaseRequest(r);

                CMS.debug("released request " + r.getRequestId());
            }
        }
    }

    public void start() {
    }

    public void stop() {
    }

    protected void transferRequest(IRequest src, IRequest dest) {
        RequestTransfer.transfer(src, dest);
    }
}

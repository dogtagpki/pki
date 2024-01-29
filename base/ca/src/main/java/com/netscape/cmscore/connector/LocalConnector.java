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

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.connector.Connector;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmsutil.http.HttpResponse;

public class LocalConnector extends Connector {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LocalConnector.class);

    IAuthority mDest = null;
    Hashtable<String, Request> mSourceReqs = new Hashtable<>();

    public LocalConnector(IAuthority dest) {
        // logger.debug("Local connector setup for source " + mSource.getId());
        mDest = dest;

        logger.debug("Local connector setup for dest " + mDest.getId());

        // register for events.
        engine.registerRequestListener(new LocalConnListener());

        logger.debug("Connector inited");
    }

    /**
     * send request to local authority.
     * returns resulting request
     */
    @Override
    public boolean send(Request r) throws EBaseException {
        logger.debug("send request type " + r.getRequestType() + " status=" + r.getRequestStatus());
        logger.debug("to " + mDest.getId() + " id=" + r.getRequestId());

        CAEngine caEngine = (CAEngine) engine;
        CertRequestRepository requestRepository = caEngine.getCertRequestRepository();
        Request destreq = requestRepository.createRequest(r.getRequestType());
        CertificateAuthority ca = caEngine.getCA();

        logger.debug("local connector dest req " +
                destreq.getRequestId() + " created for source rId " + r.getRequestId());
        //  logger.debug("setting connector dest " + mDest.getId() + " source id to " + r.getRequestId());

        // XXX set context to the real identity later.
        destreq.setSourceId(ca.getX500Name() + ":" + r.getRequestId());
        //destreq.copyContents(r);  // copy meta attributes in request.
        transferRequest(r, destreq);
        // XXX requestor type is not transferred on return.
        destreq.setExtData(Request.REQUESTOR_TYPE,
                Request.REQUESTOR_RA);
        logger.debug("connector dest " + mDest.getId() +
                " processing " + destreq.getRequestId());

        // set context before calling process request so
        // that request subsystem can record the creator
        // of the request
        SessionContext s = SessionContext.getContext();

        if (s.get(SessionContext.USER_ID) == null) {
            // use $local$ to represent it is not a user who
            // submit the request, but it is a local subsystem
            s.put(SessionContext.USER_ID, "$local$" + ca.getId());
        }

        // Locally cache the source request so that we
        // can update it when the dest request is
        // processed (when LocalConnListener is being called).
        mSourceReqs.put(r.getRequestId().toString(), r);
        try {
            RequestQueue destQ = engine.getRequestQueue();
            destQ.processRequest(destreq);
        } catch (EBaseException ex) {
            throw ex;
        } finally {
            // release the source id either success or failure
            mSourceReqs.remove(r.getRequestId().toString());
        }

        logger.debug("connector dest " + mDest.getId() +
                " processed " + destreq.getRequestId() +
                " status " + destreq.getRequestStatus());

        if (destreq.getRequestStatus() == RequestStatus.COMPLETE) {
            // no need to transfer contents if request wasn't complete.
            transferRequest(destreq, r);
            return true;
        }
        return false;
    }

    @Override
    public HttpResponse send(String op, String r) throws EBaseException {
        logger.debug("LocalConnector send() with String.  Should not get here.");
        return null;
    }

    public class LocalConnListener extends RequestListener {

        @Override
        public void init(Subsystem sys, ConfigStore config)
                throws EBaseException {
        }

        @Override
        public void set(String name, String val) {
        }

        @Override
        public void accept(Request destreq) {
            try {
                acceptImpl(destreq);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public void acceptImpl(Request destreq) throws Exception {

            logger.debug("dest " + mDest.getId() + " done with " + destreq.getRequestId());

            CAEngine engine = CAEngine.getInstance();
            RequestQueue sourceQ = engine.getRequestQueue();
            CertificateAuthority ca = engine.getCA();

            // accept requests that only belong to us.
            // XXX review death scenarios here. - If system dies anywhere
            // here need to check all requests at next server startup.
            String sourceNameAndId = destreq.getSourceId();
            String sourceName = ca.getX500Name().toString();

            if (sourceNameAndId == null ||
                    !sourceNameAndId.toString().regionMatches(0,
                            sourceName, 0, sourceName.length())) {
                logger.debug("request " + destreq.getRequestId() +
                        " from " + sourceNameAndId + " not ours.");
                return;
            }
            int index = sourceNameAndId.lastIndexOf(':');

            if (index == -1) {
                logger.error("request " + destreq.getRequestId() + " for " + sourceNameAndId + " malformed.");
                return;
            }
            String sourceId = sourceNameAndId.substring(index + 1);
            RequestId rId = new RequestId(sourceId);

            // logger.debug(mDest.getId() + " " + destreq.getRequestId() + " mapped to " + mSource.getId() + " " + rId);

            Request r = null;

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
            // RequestQueue.java for details.
            r = mSourceReqs.get(rId.toString());
            if (r != null) {
                if (r.getRequestStatus() != RequestStatus.SVC_PENDING) {
                    logger.warn("request state of " + rId + "not pending " +
                                    " from dest authority " + mDest.getId());
                    sourceQ.releaseRequest(r);
                    return;
                }
                transferRequest(destreq, r);
                sourceQ.markAsServiced(r);
                sourceQ.releaseRequest(r);

                logger.debug("released request " + r.getRequestId());
            }
        }
    }

    @Override
    public void start() {
    }

    @Override
    public void stop() {
    }

    protected void transferRequest(Request src, Request dest) {
        RequestTransfer.transfer(src, dest);
    }
}

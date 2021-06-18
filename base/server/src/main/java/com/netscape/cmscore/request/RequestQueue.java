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
package com.netscape.cmscore.request;

import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.request.AgentApprovals;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.dbs.DBSSession;
import com.netscape.cmscore.dbs.DBSubsystem;

public class RequestQueue extends ARequestQueue {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestQueue.class);

    protected DBSubsystem dbSubsystem;
    protected String mBaseDN;
    protected RequestRepository mRepository;

    /**
     * Create a request queue.
     *
     * @param policy
     *            A policy enforcement module. This object is called to make
     *            adjustments to the request, and decide whether it needs agent
     *            approval.
     * @param service
     *            The service object. This object actually performs the request
     *            after it is finalized and approved.
     * @param notifier
     *            A notifier object (optional). The notify() method of this object
     *            is invoked when the request is completed (COMPLETE, REJECTED or
     *            CANCELED states).
     * @param pendingNotifier
     *            A notifier object (optional). Like the notifier, except the
     *            notification happens if the request is made PENDING. May be the
     *            same as the 'n' argument if desired.
     * @exception EBaseException failed to retrieve request queue
     */
    public RequestQueue(
            DBSubsystem dbSubsystem,
            RequestRepository requestRepository,
            IPolicy policy,
            IService service,
            INotify notifier,
            INotify pendingNotifier)
            throws EBaseException {

        super(policy, service, notifier, pendingNotifier);

        this.dbSubsystem = dbSubsystem;
        this.mRepository = requestRepository;
        this.mBaseDN = requestRepository.getBaseDN();
    }

    @Override
    public IRequest cloneRequest(IRequest request) throws EBaseException {

        // 1. check for valid state. (Are any invalid ?)
        RequestStatus requestStatus = request.getRequestStatus();

        if (requestStatus == RequestStatus.BEGIN)
            throw new EBaseException("Invalid Status");

        // 2. create new request
        String requestType = request.getRequestType();
        IRequest clone = mRepository.createRequest(requestType);

        // 3. copy all attributes of original request to clone and modify.
        // source id (from remote authority) is not copied.
        // TODO: set the original request id to some place in the request.
        clone.copyContents(request);

        // NOT_UPDATED mean request is in memory and has
        // not been serialized to database yet. An add
        // operation is required to serialize a NOT_UPDATED
        // request.
        clone.setExtData("dbStatus", "NOT_UPDATED");

        return clone;
    }

    public IRequest findRequest(RequestId id) throws EBaseException {
        return mRepository.readRequest(id);
    }

    @Override
    public void updateRequest(IRequest request) throws EBaseException {

        String name = getUserIdentity();
        if (name != null) {
            request.setExtData(IRequest.UPDATED_BY, name);
        }

        String delayLDAPCommit = request.getExtDataInString("delayLDAPCommit");
        ((Request) request).mModificationTime = new Date();

        if (delayLDAPCommit != null && delayLDAPCommit.equals("true")) {
            // delay writing to LDAP
            return;
        }

        // TODO: use a state flag to determine whether to call
        // addRequest or modifyRequest (see newRequest as well)

        String dbStatus = request.getExtDataInString("dbStatus");
        if (dbStatus.equals("UPDATED")) {
            mRepository.modifyRequest(request);
            return;
        }

        request.setExtData("dbStatus", "UPDATED");
        mRepository.addRequest(request);
    }

    @Override
    public void markRequestPending(IRequest request) throws EBaseException {

        RequestStatus rs = request.getRequestStatus();

        if (rs != RequestStatus.BEGIN) {
            throw new EBaseException("Invalid request status: " + rs);
        }

        // Change the request state. This method of making a
        // request PENDING does NOT invoke the PENDING notifiers.
        // To change this, just call stateEngine at the completion
        // of this routine.
        request.setRequestStatus(RequestStatus.PENDING);

        updateRequest(request);
        stateEngine(request);
    }

    @Override
    public void cancelRequest(IRequest request) throws EBaseException {

        request.setRequestStatus(RequestStatus.CANCELED);

        updateRequest(request);
        stateEngine(request);
    }

    @Override
    public void rejectRequest(IRequest request) throws EBaseException {

        RequestStatus rs = request.getRequestStatus();

        if (rs != RequestStatus.PENDING) {
            throw new EBaseException("Invalid request status: " + rs);
        }

        request.setRequestStatus(RequestStatus.REJECTED);
        updateRequest(request);

        stateEngine(request); // does nothing
    }

    @Override
    public void approveRequest(IRequest request) throws EBaseException {

        RequestStatus rs = request.getRequestStatus();

        if (rs != RequestStatus.PENDING) {
            throw new EBaseException("Invalid request status: " + rs);
        }

        Vector<String> list = request.getExtDataInStringVector(AgentApprovals.class.getName());
        AgentApprovals aas = AgentApprovals.fromStringVector(list);

        if (aas == null) {
            aas = new AgentApprovals();
        }

        String agentName = getUserIdentity();

        if (agentName == null) {
            throw new EBaseException("Missing agent information");
        }

        aas.addApproval(agentName);
        request.setExtData(AgentApprovals.class.getName(), aas.toStringVector());

        PolicyResult pr = mPolicy.apply(request);

        if (pr == PolicyResult.ACCEPTED) {
            request.setRequestStatus(RequestStatus.APPROVED);

        } else if (pr == PolicyResult.DEFERRED || pr == PolicyResult.REJECTED) {
            // ignore
        }

        updateRequest(request);
        stateEngine(request);
    }

    @Override
    public void markAsServiced(IRequest request) throws EBaseException {

        request.setRequestStatus(RequestStatus.COMPLETE);

        updateRequest(request);

        if (mNotify != null) {
            mNotify.notify(request);
        }
    }

    @Override
    public RequestId findRequestBySourceId(String id) {
        IRequestList irl = findRequestsBySourceId(id);

        if (irl == null)
            return null;

        return irl.nextRequestId();
    }

    @Override
    public IRequestList findRequestsBySourceId(String id) {
        IDBSearchResults results = null;
        DBSSession dbs = null;

        // Need only the requestid in the result of the search
        // TODO: generic search returning RequestId
        String filter = "(" + RequestRecord.ATTR_SOURCE_ID + "=" + id + ")";

        try {
            dbs = dbSubsystem.createSession();
            results = dbs.search(mBaseDN, filter);
        } catch (EBaseException e) {
            logger.error("Error in Ldap Request searching code: " + e.getMessage(), e);
        } finally {
            // Close session - ignoring errors (UTIL)
            if (dbs != null)
                try {
                    dbs.close();
                } catch (EBaseException e) {
                }
        }

        if (results == null || !results.hasMoreElements())
            return null;

        return new SearchEnumeration(results);

    }

    @Override
    protected Enumeration<RequestId> getRawList() {
        IDBSearchResults results = null;
        DBSSession dbs = null;

        try {
            dbs = dbSubsystem.createSession();
            results = dbs.search(mBaseDN, "(requestId=*)");
        } catch (EBaseException e) {
            logger.warn("RequestQueue: " + e.getMessage(), e);
        } finally {
            // Close session - ignoring errors (UTIL)
            if (dbs != null)
                try {
                    dbs.close();
                } catch (EBaseException e) {
                }
        }

        if (results == null)
            return null;

        return new SearchEnumeration(results);
    }

    @Override
    public IRequestList listRequestsByStatus(RequestStatus s) {
        IDBSearchResults results = null;
        DBSSession dbs = null;

        try {
            String f1;
            String f2;

            f1 = "(" + RequestRecord.ATTR_REQUEST_STATE + "=" + s + ")";
            f2 = "(" + RequestRecord.ATTR_REQUEST_ID + "=*)";

            f1 = "(&" + f1 + f2 + ")";

            dbs = dbSubsystem.createSession();
            results = dbs.search(mBaseDN, f1);
        } catch (EBaseException e) {
            //System.err.println("Error: "+e);
            //e.printStackTrace();
        } finally {
            // Close session - ignoring errors (UTIL)
            if (dbs != null)
                try {
                    dbs.close();
                } catch (EBaseException e) {
                }
        }

        if (results == null)
            return null;

        return new SearchEnumeration(results);
    }

    /*
     * list record attributes (debugging output)
     */
    static void listRecordAttrs(String s, Hashtable<String, Object> h) {
        System.err.println(s);
        Enumeration<String> e = h.keys();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            System.err.println("Attr: " + name + " Value: " + h.get(name));
        }
    }

    /**
     * Recovers from a crash. Resends all requests that are in
     * the APPROVED state.
     */
    @Override
    public void recoverWillBlock() {

        IRequestList list = listRequestsByStatus(RequestStatus.APPROVED);

        if (list == null) {
            return;
        }

        while (list.hasMoreElements()) {
            RequestId requestID = list.nextRequestId();

            try {
                IRequest request = mRepository.readRequest(requestID);

                // Recheck the status - should be the same!!
                if (request.getRequestStatus() == RequestStatus.APPROVED) {
                    stateEngine(request);
                }

                releaseRequest(request);

            } catch (EBaseException e) {
                logger.warn("RequestQueue: " + e.getMessage(), e);
            }
        }
    }
}

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

import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.request.AgentApprovals;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.request.RequestScheduler;
import com.netscape.cmscore.dbs.DBSubsystem;

/**
 * This class represents the request queue within the
 * certificate server. This class implements the state
 * engine for processing request objects.
 *
 * There are several queues, such as KRA and CA requests.
 * Each of these request queues has a defined
 * set of policies, a notification service (for request
 * completion) and a service routine. The request queue
 * provides an interface for creating and viewing requests,
 * as well as performing operations on them.
 *
 * !Put state machine description here!
 *
 * This class also provides several accessor functions for
 * setting fields in the request object. These functions are
 * provided for saving and restoring the state in the database.
 *
 * This class also implements the locking operations.
 *
 * @author thayes
 * @version $Revision$ $Date$
 */
public class RequestQueue {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestQueue.class);

    /**
     * Global request version for tracking request changes.
     */
    public final static String REQUEST_VERSION = "1.0.0";

    // RequestIDTable mTable = new RequestIDTable();

    IPolicy mPolicy;
    IService mService;
    RequestNotifier mNotify;
    RequestNotifier mPendingNotify;

    RequestScheduler mRequestScheduler;

    protected DBSubsystem dbSubsystem;
    protected String mBaseDN;
    protected RequestRepository requestRepository;

    /**
     * Create a request queue.
     *
     * @param policy A policy enforcement module. This object is called to make
     *  adjustments to the request, and decide whether it needs agent approval.
     * @param service The service object. This object actually performs the request
     *  after it is finalized and approved.
     * @param notifier A notifier object (optional). The notify() method of this object
     *  is invoked when the request is completed (COMPLETE, REJECTED or CANCELED states).
     * @param pendingNotifier A notifier object (optional). Like the notifier, except the
     *  notification happens if the request is made PENDING. May be the same as the 'n'
     *  argument if desired.
     * @exception EBaseException failed to retrieve request queue
     */
    public RequestQueue(
            DBSubsystem dbSubsystem,
            RequestRepository requestRepository,
            IPolicy policy,
            IService service,
            RequestNotifier notifier,
            RequestNotifier pendingNotifier)
            throws EBaseException {

        this.mPolicy = policy;
        this.mService = service;
        this.mNotify = notifier;
        this.mPendingNotify = pendingNotifier;
        this.dbSubsystem = dbSubsystem;
        this.requestRepository = requestRepository;
        this.mBaseDN = requestRepository.getBaseDN();
    }

    /**
     * Gets request scheduler.
     *
     * @return request scheduler
     */
    public RequestScheduler getRequestScheduler() {
        return mRequestScheduler;
    }

    /**
     * Sets request scheduler.
     *
     * @param scheduler request scheduler
     */
    public void setRequestScheduler(RequestScheduler scheduler) {
        mRequestScheduler = scheduler;
    }

    /**
     * Clones a request object. A new request id is assigned
     * and all attributes of the request is copied to cloned request,
     * except for the sourceID of the original request
     * (remote authority's request ID).
     *
     * The cloned request that is returned is LOCKED.
     * The caller MUST release the request object by calling releaseRequest().
     *
     * @param request request to be cloned
     * @return cloned request
     * @exception EBaseException failed to clone request
     */
    public Request cloneRequest(Request request) throws EBaseException {

        // 1. check for valid state. (Are any invalid ?)
        RequestStatus requestStatus = request.getRequestStatus();

        if (requestStatus == RequestStatus.BEGIN)
            throw new EBaseException("Invalid Status");

        // 2. create new request
        String requestType = request.getRequestType();
        Request clone = requestRepository.createRequest(requestType);

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

    public Request findRequest(RequestId id) throws EBaseException {
        return requestRepository.readRequest(id);
    }

    /**
     * Get the identity of the current user
     */
    protected String getUserIdentity() {
        SessionContext s = SessionContext.getContext();
        return (String) s.get(SessionContext.USER_ID);
    }

    protected void stateEngine(Request r) throws EBaseException {
        boolean complete = false;

        while (!complete) {
            RequestStatus rs = r.getRequestStatus();

            if (rs == RequestStatus.BEGIN) {
                PolicyResult pr = PolicyResult.ACCEPTED;

                if (mPolicy != null)
                    pr = mPolicy.apply(r);

                if (pr == PolicyResult.ACCEPTED) {
                    r.setRequestStatus(RequestStatus.APPROVED);
                } else if (pr == PolicyResult.DEFERRED) {
                    r.setRequestStatus(RequestStatus.PENDING);
                } else {
                    r.setRequestStatus(RequestStatus.REJECTED);
                }

                // if policy accepts the request, the request
                // will be processed right away. So speed up
                // the request processing, we do not want to
                // have too many db operation.
                if (pr != PolicyResult.ACCEPTED) {
                    requestRepository.updateRequest(r);
                }
            } else if (rs == RequestStatus.PENDING) {
                if (mPendingNotify != null)
                    mPendingNotify.notify(r);

                complete = true;
            } else if (rs == RequestStatus.APPROVED) {
                boolean svcComplete;

                svcComplete = mService.serviceRequest(r);

                // Completed requests call the notifier and are done. Others
                // wait for the serviceComplete call.
                if (svcComplete) {
                    r.setRequestStatus(RequestStatus.COMPLETE);
                } else {
                    r.setRequestStatus(RequestStatus.SVC_PENDING);
                }

                requestRepository.updateRequest(r);
            } else if (rs == RequestStatus.SVC_PENDING) {
                complete = true;
            } else if (rs == RequestStatus.CANCELED) {
                if (mNotify != null)
                    mNotify.notify(r);

                complete = true;
            } else if (rs == RequestStatus.REJECTED) {
                if (mNotify != null)
                    mNotify.notify(r);

                complete = true;
            } else if (rs == RequestStatus.COMPLETE) {
                if (mNotify != null)
                    mNotify.notify(r);

                complete = true;
            }
        }
    }

    /**
     * Puts a new request into the PENDING state. This call is
     * only valid for requests with status BEGIN. An error is
     * generated for other cases.
     *
     * This call might be used by agent servlets that want to copy
     * a previous request, and resubmit it.
     * By putting it into PENDING state, the normal agent screens
     * can be used for further processing.
     *
     * @param request the request to mark PENDING
     * @exception EBaseException failed to mark request as pending
     */
    public void markRequestPending(Request request) throws EBaseException {

        RequestStatus rs = request.getRequestStatus();

        if (rs != RequestStatus.BEGIN) {
            throw new EBaseException("Invalid request status: " + rs);
        }

        // Change the request state. This method of making a
        // request PENDING does NOT invoke the PENDING notifiers.
        // To change this, just call stateEngine at the completion
        // of this routine.
        request.setRequestStatus(RequestStatus.PENDING);

        requestRepository.updateRequest(request);
        stateEngine(request);
    }

    /**
     * Clones a request object and mark it pending. A new request id is assigned
     * and all attributes of the request is copied to cloned request,
     * except for the sourceID of the original request
     * (remote authority's request ID).
     *
     * The cloned request that is returned is LOCKED.
     * The caller MUST release the request object by calling releaseRequest().
     *
     * @param r request to be cloned
     * @return cloned request mark PENDING
     * @exception EBaseException failed to clone or mark request
     */
    public Request cloneAndMarkPending(Request r) throws EBaseException {
        Request clone = cloneRequest(r);
        markRequestPending(clone);
        return clone;
    }

    /**
     * Cancels a request. The request must be locked.
     *
     * This call will fail if: the request is not in PENDING state
     *
     * The agent servlet (or other application) may wish to store
     * AgentMessage values to indicate the reason for the action
     *
     * @param request the request that is being canceled
     * @exception EBaseException failed to cancel request
     */
    public void cancelRequest(Request request) throws EBaseException {

        request.setRequestStatus(RequestStatus.CANCELED);

        requestRepository.updateRequest(request);
        stateEngine(request);
    }

    /**
     * Rejects a request. The request must be locked.
     *
     * This call will fail if: the request is not in PENDING state
     *
     * The agent servlet (or other application) may wish to store
     * AgentMessage values to indicate the reason for the action
     *
     * @param request the request that is being rejected
     * @exception EBaseException failed to reject request
     */
    public void rejectRequest(Request request) throws EBaseException {

        RequestStatus rs = request.getRequestStatus();

        if (rs != RequestStatus.PENDING) {
            throw new EBaseException("Invalid request status: " + rs);
        }

        request.setRequestStatus(RequestStatus.REJECTED);
        requestRepository.updateRequest(request);

        stateEngine(request); // does nothing
    }

    /**
     * Approves a request. The request must be locked.
     *
     * This call will fail if: the request is not in PENDING state
     * the policy modules do not accept the request
     *
     * If the policy modules reject the request, then the request
     * will remain in the PENDING state. Messages from the
     * policy module can be display to the agent to indicate the
     * source of the problem.
     *
     * The request processing code adds an AgentApproval to this request
     * that contains the authentication id of the agent.
     * This data is retrieved from the Session object (qv).
     *
     * @param request the request that is being approved
     * @exception EBaseException failed to approve request
     */
    public void approveRequest(Request request) throws EBaseException {

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

        requestRepository.updateRequest(request);
        stateEngine(request);
    }

    /**
     * Marks as serviced after destination authority has serviced request.
     * Used by connector.
     *
     * Caller must lock request and release request.
     *
     * @param request request
     */
    public void markAsServiced(Request request) throws EBaseException {

        request.setRequestStatus(RequestStatus.COMPLETE);

        requestRepository.updateRequest(request);

        if (mNotify != null) {
            mNotify.notify(request);
        }
    }

    /**
     * Locates a request from the SourceId.
     *
     * @param id a unique identifier for the record that is based on the source
     *  of the request, and possibly an identify assigned by the source.
     * @return The requestid corresponding to this source id. null is
     *  returned if the source id does not exist.
     */
    public RequestId findRequestBySourceId(String id) throws EBaseException {
        Collection<RequestRecord> records = requestRepository.findRequestsBySourceId(id);

        if (records.isEmpty())
            return null;

        RequestRecord record = records.iterator().next();
        return record.getRequestId();
    }

    /**
     * Protected access for setting the modification time of a request.
     *
     * @param request The request to be modified.
     * @param date The new value for the time.
     */
    protected void setModificationTime(Request request, Date date) {
        request.mModificationTime = date;
    }

    /**
     * Protected access for setting the creation time of a request.
     *
     * @param request The request to be modified.
     * @param date The new value for the time.
     */
    protected void setCreationTime(Request request, Date date) {
        request.mCreationTime = date;
    }

    /**
     * Returns an enumerator that lists all RequestIds for requests
     * that are in the given status. For example, all the PENDING
     * requests could be listed by specifying RequestStatus.PENDING
     * as the <i>status</i> argument
     *
     * NOTE: This interface will not be useful for large databases.
     * This needs to be replace by a VLV (paged) search object.
     *
     * Should be overridden by the specialized class if a more
     * efficient method is available for implementing this operation.
     *
     * @param s request status
     * @return request list
     */
    public Collection<RequestRecord> listRequestsByStatus(RequestStatus s) throws EBaseException {
        String f1 = "(" + RequestRecord.ATTR_REQUEST_STATE + "=" + s + ")";
        String f2 = "(" + RequestRecord.ATTR_REQUEST_ID + "=*)";
        String filter = "(&" + f1 + f2 + ")";
        return requestRepository.listRequestsByFilter(filter);
    }

    /**
     * Gets requests that are pending on handling by the service
     *
     * @return list of pending requests
     */
    // public IRequestList listServicePendingRequests();

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
    public void recoverWillBlock() throws Exception {

        Collection<RequestRecord> records = listRequestsByStatus(RequestStatus.APPROVED);

        for (RequestRecord record : records) {
            Request request = record.toRequest();

            try {
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

    /**
     * Retrieves the notifier for pending request.
     *
     * @return notifier for pending request
     */
    public RequestNotifier getPendingNotify() {
        return mPendingNotify;
    }

    /**
     * Begins processing for this request. This call
     * is valid only on requests with status BEGIN
     * An error is generated for other cases.
     *
     * @param r request to be processed
     * @exception EBaseException failed to process request
     */
    public void processRequest(Request r) throws EBaseException {

        // #610553 Thread Scheduler
        RequestScheduler scheduler = getRequestScheduler();

        if (scheduler != null) {
            scheduler.requestIn(r);
        }

        try {
            // 1. Check for valid state
            RequestStatus rs = r.getRequestStatus();

            if (rs != RequestStatus.BEGIN) {
                throw new EBaseException("Invalid Status");
            }

            stateEngine(r);

        } finally {
            if (scheduler != null) {
                scheduler.requestOut(r);
            }
        }
    }

    /**
     * log a change in the request status
     */
    protected void logChange(Request request) {
        // write the queue name and request id
        // write who changed it
        // write what change (which state change) was made
        //   - new (processRequest)
        //   - approve
        //   - reject

        // Ordering
        //  - make change in memory
        //  - log change and result
        //  - update record
    }

    /**
     * Releases the LOCK on a request obtained from findRequest() or
     * newRequest()
     *
     * @param request request
     */
    public final void releaseRequest(Request request) {
        // mTable.unlock(request.getRequestId());
    }
}

//
// Table of RequestId values that are currently in use by some thread.
// The fact that the request is in this table constitutes a lock
// on the value.
//
/*
class RequestIDTable {

    // instance variables
    Hashtable mHashtable = new Hashtable();

    public synchronized void lock(RequestId id) {
        while (true) {
            if (mHashtable.put(id, id) == null)
                break;

            try {
                wait();
            } catch (InterruptedException e) {
            };
        }
    }

    public synchronized void unlock(RequestId id) {
        mHashtable.remove(id);
        notifyAll();
    }
}
*/

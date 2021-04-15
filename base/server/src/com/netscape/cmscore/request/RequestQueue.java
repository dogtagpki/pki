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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IService;
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
     * @param name
     *            the name of the request queue. (Ex: "ca" "ra")
     * @param policy
     *            A policy enforcement module. This object is called to make
     *            adjustments to the request, and decide whether it needs agent
     *            approval.
     * @param service
     *            The service object. This object actually performs the request
     *            after it is finalized and approved.
     * @param notiifer
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

    public RequestId findRequestBySourceId(String id) {
        IRequestList irl = findRequestsBySourceId(id);

        if (irl == null)
            return null;

        return irl.nextRequestId();
    }

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

    /**
     */
    public IRequestList listRequestsByFilter(String f, int maxSize) {
        IDBSearchResults results = null;
        DBSSession dbs = null;

        try {
            dbs = dbSubsystem.createSession();
            results = dbs.search(mBaseDN, f, maxSize);
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

    /**
     */
    public IRequestList listRequestsByFilter(String f, int maxSize, int timeLimit) {
        IDBSearchResults results = null;
        DBSSession dbs = null;

        try {
            dbs = dbSubsystem.createSession();
            results = dbs.search(mBaseDN, f, maxSize, timeLimit);
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
}

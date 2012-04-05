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

import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.repository.IRepository;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestRecord;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.request.ldap.IRequestMod;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.util.Debug;

public class RequestQueue
        extends ARequestQueue
        implements IRequestMod {
    // ARequestQueue.newRequestId
    protected RequestId newRequestId()
            throws EBaseException {
        // get the next request Id
        BigInteger next = mRepository.getNextSerialNumber();

        RequestId rid = new RequestId(next);

        return rid;
    }

    protected IRequest readRequest(RequestId id) {
        RequestRecord record;

        // String name = Schema.LDAP_ATTR_REQUEST_ID + "=" +
        String name = "cn" + "=" +
                id + "," + mBaseDN;

        Object obj = null;
        IDBSSession dbs = null;

        try {
            dbs = mDB.createSession();
            obj = dbs.read(name);
        } catch (EBaseException e) {
            Debug.trace("Error: " + e);
            Debug.printStackTrace(e);
        } finally {
            // Close session - ignoring errors (UTIL)
            if (dbs != null)
                try {
                    dbs.close();
                } catch (EBaseException e) {
                }
        }

        // TODO Errors!!!
        if (obj == null || !(obj instanceof RequestRecord))
            return null;

        record = (RequestRecord) obj;

        /*
         setRequestStatus(r, record.mRequestState);
         r.setSourceId(record.mSourceId);
         r.setRequestOwner(record.mOwner);
         record.storeAttrs(r, record.mRequestAttrs);
         setModificationTime(r, record.mModifyTime);
         setCreationTime(r, record.mCreateTime);
         */
        return makeRequest(record);
    }

    protected void addRequest(IRequest r) throws EBaseException {
        // setup to call dbs.add(name, IAttrSet)
        RequestRecord record = new RequestRecord();

        record.add(r);

        // compute the name of the object
        // String name = Schema.LDAP_ATTR_REQUEST_ID + "=" +
        String name = "cn" + "=" +
                record.mRequestId + "," + mBaseDN;

        IDBSSession dbs = null;

        try {
            dbs = mDB.createSession();
            dbs.add(name, record);
        } catch (EBaseException e) {
            Debug.trace("Error: " + e);
            Debug.printStackTrace(e);
            throw e;
        } finally {
            // Close session - ignoring errors (UTIL)
            if (dbs != null)
                try {
                    dbs.close();
                } catch (EBaseException e) {
                }
        }
    }

    protected void modifyRequest(IRequest r) {
        String dbStatus = r.getExtDataInString("dbStatus");

        if (!dbStatus.equals("UPDATED")) {
            try {
                r.setExtData("dbStatus", "UPDATED");
                addRequest(r);
            } catch (EBaseException e) {
                System.out.println(e.toString());
            }
            return;
        }

        ModificationSet mods = new ModificationSet();

        try {
            RequestRecord.mod(mods, r);
        } catch (EBaseException e) {
            Debug.trace("Error: " + e);
            Debug.printStackTrace(e);
        }

        /*
         //
         mods.add(IRequestRecord.ATTR_REQUEST_STATE,
         Modification.MOD_REPLACE, r.getRequestStatus());

         mods.add(IRequestRecord.ATTR_SOURCE_ID,
         Modification.MOD_REPLACE, r.getSourceId());

         mods.add(IRequestRecord.ATTR_REQUEST_OWNER,
         Modification.MOD_REPLACE, r.getRequestOwner());

         mods.add(IRequestRecord.ATTR_MODIFY_TIME,
         Modification.MOD_REPLACE, r.getModificationTime());

         java.util.Hashtable ht = RequestRecord.loadAttrs(r);
         mods.add(RequestRecord.ATTR_REQUEST_ATTRS,
         Modification.MOD_REPLACE, ht);
         */

        // String name = Schema.LDAP_ATTR_REQUEST_ID + "=" +
        String name = "cn" + "=" +
                r.getRequestId() + "," + mBaseDN;

        IDBSSession dbs = null;

        try {
            dbs = mDB.createSession();
            dbs.modify(name, mods);
        } catch (EBaseException e) {
            Debug.trace("Error: " + e);
            Debug.printStackTrace(e);
        } finally {
            // Close session - ignoring errors (UTIL)
            if (dbs != null)
                try {
                    dbs.close();
                } catch (EBaseException e) {
                }
        }
    }

    IRequest makeRequest(RequestRecord record) {
        IRequest r = createRequest(record.mRequestId, record.mRequestType);

        try {
            // convert (copy) fields
            record.read(this, r);
        } catch (EBaseException e) {
            Debug.trace("Error: " + e);
            Debug.printStackTrace(e);
        }

        return r;
    }

    public void modRequestStatus(IRequest r, RequestStatus s) {
        setRequestStatus(r, s);
    }

    public void modCreationTime(IRequest r, Date d) {
        setCreationTime(r, d);
    }

    public void modModificationTime(IRequest r, Date d) {
        setModificationTime(r, d);
    }

    /**
     * Resets serial number.
     */
    public void resetSerialNumber(BigInteger serial) throws EBaseException {
        mRepository.resetSerialNumber(serial);
    }

    /**
     * Removes all objects with this repository.
     */
    public void removeAllObjects() throws EBaseException {
        mRepository.removeAllObjects();
    }

    public BigInteger getLastRequestIdInRange(BigInteger reqId_low_bound, BigInteger reqId_upper_bound) {
        CMS.debug("RequestQueue: getLastRequestId: low " + reqId_low_bound + " high " + reqId_upper_bound);
        if (reqId_low_bound == null || reqId_upper_bound == null || reqId_low_bound.compareTo(reqId_upper_bound) >= 0) {
            CMS.debug("RequestQueue: getLastRequestId: bad upper and lower bound range.");
            return null;
        }

        String filter = "(" + "requeststate" + "=*" + ")";

        RequestId fromId = new RequestId(reqId_upper_bound);

        CMS.debug("RequestQueue: getLastRequestId: filter " + filter + " fromId " + fromId);
        ListEnumeration recList = (ListEnumeration) getPagedRequestsByFilter(fromId, filter, 5 * -1, "requestId");

        int size = recList.getSize();

        CMS.debug("RequestQueue: getLastRequestId: size   " + size);

        int ltSize = recList.getSizeBeforeJumpTo();

        CMS.debug("RequestQueue: getSizeBeforeJumpTo: " + ltSize);

        if (size <= 0) {
            CMS.debug("RequestQueue: getLastRequestId:  request list is empty.");

            BigInteger ret = new BigInteger(reqId_low_bound.toString(10));

            ret = ret.add(new BigInteger("-1"));

            CMS.debug("CertificateRepository:getLastCertRecordSerialNo: returning " + ret);
            return ret;
        }

        IRequest curRec = null;

        RequestId curId = null;

        String reqId = null;

        for (int i = 0; i < 5; i++) {
            curRec = recList.getElementAt(i);

            if (curRec != null) {

                curId = curRec.getRequestId();

                reqId = curId.toString();

                CMS.debug("RequestQueue: curReqId: " + reqId);

                BigInteger curIdInt = new BigInteger(reqId);

                if (((curIdInt.compareTo(reqId_low_bound) == 0) || (curIdInt.compareTo(reqId_low_bound) == 1)) &&
                        ((curIdInt.compareTo(reqId_upper_bound) == 0) || (curIdInt.compareTo(reqId_upper_bound) == -1))) {
                    CMS.debug("RequestQueue: getLastRequestId : returning value " + curIdInt);
                    return curIdInt;
                }

            }

        }

        BigInteger ret = new BigInteger(reqId_low_bound.toString(10));

        ret = ret.add(new BigInteger("-1"));

        CMS.debug("CertificateRepository:getLastCertRecordSerialNo: returning " + ret);
        return ret;

    }

    /**
     * Implements IRequestQueue.findRequestBySourceId
     * <p>
     *
     * @see com.netscape.certsrv.request.IRequestQueue#findRequestBySourceId
     */
    public RequestId findRequestBySourceId(String id) {
        IRequestList irl = findRequestsBySourceId(id);

        if (irl == null)
            return null;

        return irl.nextRequestId();
    }

    /**
     * Implements IRequestQueue.findRequestsBySourceId
     * <p>
     *
     * @see com.netscape.certsrv.request.IRequestQueue#findRequestsBySourceId
     */
    public IRequestList findRequestsBySourceId(String id) {
        IDBSearchResults results = null;
        IDBSSession dbs = null;

        // Need only the requestid in the result of the search
        // TODO: generic search returning RequestId
        String filter = "(" + IRequestRecord.ATTR_SOURCE_ID + "=" + id + ")";

        try {
            dbs = mDB.createSession();
            results = dbs.search(mBaseDN, filter);
        } catch (EBaseException e) {
            Debug.trace("Error in Ldap Request searching code: " + e);
            Debug.printStackTrace(e);
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

        return new SearchEnumeration(this, results);

    }

    protected Enumeration<RequestId> getRawList() {
        IDBSearchResults results = null;
        IDBSSession dbs = null;

        try {
            dbs = mDB.createSession();
            results = dbs.search(mBaseDN, "(requestId=*)");
        } catch (EBaseException e) {
            Debug.trace("Error: " + e);
            Debug.printStackTrace(e);
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

        return new SearchEnumeration(this, results);
    }

    /**
     */
    public IRequestList listRequestsByFilter(String f) {
        IDBSearchResults results = null;
        IDBSSession dbs = null;

        try {
            dbs = mDB.createSession();
            results = dbs.search(mBaseDN, f);
        } catch (EBaseException e) {
            Debug.trace("Error: " + e);
            Debug.printStackTrace(e);
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

        return new SearchEnumeration(this, results);
    }

    /**
     */
    public IRequestList listRequestsByFilter(String f, int maxSize) {
        IDBSearchResults results = null;
        IDBSSession dbs = null;

        try {
            dbs = mDB.createSession();
            results = dbs.search(mBaseDN, f, maxSize);
        } catch (EBaseException e) {
            Debug.trace("Error: " + e);
            Debug.printStackTrace(e);
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

        return new SearchEnumeration(this, results);
    }

    /**
     */
    public IRequestList listRequestsByFilter(String f, int maxSize, int timeLimit) {
        IDBSearchResults results = null;
        IDBSSession dbs = null;

        try {
            dbs = mDB.createSession();
            results = dbs.search(mBaseDN, f, maxSize, timeLimit);
        } catch (EBaseException e) {
            Debug.trace("Error: " + e);
            Debug.printStackTrace(e);
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

        return new SearchEnumeration(this, results);
    }

    public IRequestList listRequestsByStatus(RequestStatus s) {
        IDBSearchResults results = null;
        IDBSSession dbs = null;

        try {
            String f1;
            String f2;

            f1 = "(" + IRequestRecord.ATTR_REQUEST_STATE + "=" + s + ")";
            f2 = "(" + IRequestRecord.ATTR_REQUEST_ID + "=*)";

            f1 = "(&" + f1 + f2 + ")";

            dbs = mDB.createSession();
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

        return new SearchEnumeration(this, results);
    }

    /*
     * Implements IRequestQueue.getPagedRequests
     */
    public IRequestVirtualList getPagedRequests(int pageSize) {
        return getPagedRequestsByFilter("(requestId=*)", pageSize, "requestId");
    }

    /*
     * Implements IRequestQueue.getPagedRequestsByFilter
     */
    public IRequestVirtualList
            getPagedRequestsByFilter(String filter, int pageSize, String sortKey) {
        return getPagedRequestsByFilter(null, filter, pageSize, sortKey);
    }

    public IRequestVirtualList
            getPagedRequestsByFilter(RequestId from, String filter, int pageSize,
                    String sortKey) {
        return getPagedRequestsByFilter(from, false, filter, pageSize, sortKey);
    }

    public IRequestVirtualList
            getPagedRequestsByFilter(RequestId from, boolean jumpToEnd, String filter, int pageSize,
                    String sortKey) {
        IDBVirtualList<Object> results = null;
        IDBSSession dbs = null;

        try {
            dbs = mDB.createSession();
        } catch (EBaseException e) {
            return null;
        }

        try {

            if (from == null) {
                results = dbs.createVirtualList(mBaseDN, filter, (String[]) null,
                            sortKey, pageSize);
            } else {
                int len = from.toString().length();
                String internalRequestId = null;

                if (jumpToEnd) {
                    internalRequestId = "99";
                } else {
                    if (len > 9) {
                        internalRequestId = Integer.toString(len) + from.toString();
                    } else {
                        internalRequestId = "0" + Integer.toString(len) +
                                from.toString();
                    }
                }

                results = dbs.createVirtualList(mBaseDN, filter, (String[]) null,
                            internalRequestId, sortKey, pageSize);
            }
        } catch (EBaseException e) {
            return null;
        } finally {
            try {
                dbs.close();
            } catch (EBaseException e) {
            }
        }

        try {
            results.setSortKey(sortKey);
        } catch (EBaseException e) {//XXX
            System.out.println(e.toString());
            return null;
        }

        return new ListEnumeration(this, results);
    }

    public RequestQueue(String name, int increment, IPolicy p, IService s, INotify n,
            INotify pendingNotify)
            throws EBaseException {
        super(p, s, n, pendingNotify);

        mDB = DBSubsystem.getInstance();
        mBaseDN = "ou=" + name + ",ou=requests," + mDB.getBaseDN();

        mRepository = new RequestRepository(name, increment, mDB, this);

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

    /*
     * return request repository
     */
    public IRepository getRequestRepository() {
        return mRepository;
    }

    public String getPublishingStatus() {
        return mRepository.getPublishingStatus();
    }

    public void setPublishingStatus(String status) {
        mRepository.setPublishingStatus(status);
    }

    protected String mBaseDN;
    protected IDBSubsystem mDB;
    protected RequestRepository mRepository;
}

class SearchEnumeration
        implements IRequestList {
    public RequestId nextRequestId() {
        Object obj;

        obj = mResults.nextElement();

        if (obj == null || !(obj instanceof RequestRecord))
            return null;

        RequestRecord r = (RequestRecord) obj;

        return r.mRequestId;
    }

    public boolean hasMoreElements() {
        return mResults.hasMoreElements();
    }

    public RequestId nextElement() {
        return nextRequestId();
    }

    public SearchEnumeration(IDBSearchResults r) {
        mResults = r;
    }

    public SearchEnumeration(RequestQueue queue, IDBSearchResults r) {
        mResults = r;
        mQueue = queue;
    }

    public Object nextRequest() {
        Object obj;

        obj = mResults.nextElement();

        if (obj == null || !(obj instanceof RequestRecord))
            return null;

        RequestRecord r = (RequestRecord) obj;

        return r;
    }

    public IRequest nextRequestObject() {
        RequestRecord record = (RequestRecord) nextRequest();
        if (record != null)
            return mQueue.makeRequest(record);
        return null;
    }

    protected IDBSearchResults mResults;
    protected RequestQueue mQueue;
}

class ListEnumeration
        implements IRequestVirtualList {
    public IRequest getElementAt(int i) {
        RequestRecord record = (RequestRecord) mList.getElementAt(i);

        if (record == null)
            return null;

        return mQueue.makeRequest(record);
    }

    public int getCurrentIndex() {
        return mList.getCurrentIndex();
    }

    public int getSize() {
        return mList.getSize();
    }

    public int getSizeBeforeJumpTo() {
        return mList.getSizeBeforeJumpTo();

    }

    public int getSizeAfterJumpTo() {
        return mList.getSizeAfterJumpTo();

    }

    ListEnumeration(RequestQueue queue, IDBVirtualList<Object> list) {
        mQueue = queue;
        mList = list;
    }

    protected RequestQueue mQueue;
    protected IDBVirtualList<Object> mList;
}

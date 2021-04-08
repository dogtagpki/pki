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
import java.security.SecureRandom;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.request.ldap.IRequestMod;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.dbs.DBSSession;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.security.JssSubsystem;

public class RequestQueue
        extends ARequestQueue
        implements IRequestMod {

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

    // ARequestQueue.newRequestId
    public RequestId newRequestId() throws EBaseException {

        // get the next request Id
        BigInteger next = mRepository.getNextSerialNumber();

        RequestId rid = new RequestId(next);

        return rid;
    }

    public RequestId newEphemeralRequestId() {

        CMSEngine engine = CMS.getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        SecureRandom random = jssSubsystem.getRandomNumberGenerator();
        long id = System.currentTimeMillis() * 10000 + random.nextInt(10000);
        return new RequestId(id);
    }

    protected IRequest readRequest(RequestId id) {
        RequestRecord record;

        // String name = Schema.LDAP_ATTR_REQUEST_ID + "=" +
        String name = "cn" + "=" +
                id + "," + mBaseDN;

        Object obj = null;
        DBSSession dbs = null;

        try {
            dbs = dbSubsystem.createSession();
            obj = dbs.read(name);
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

        DBSSession dbs = null;

        try {
            dbs = dbSubsystem.createSession();
            dbs.add(name, record);
        } catch (EBaseException e) {
            logger.error("RequestQueue: " + e.getMessage(), e);
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
            logger.warn("RequestQueue: " + e.getMessage(), e);
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

        DBSSession dbs = null;

        try {
            dbs = dbSubsystem.createSession();
            dbs.modify(name, mods);
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
    }

    IRequest makeRequest(RequestRecord record) {
        Request r = new Request(record.mRequestId);

        try {
            // convert (copy) fields
            record.read(this, r);
        } catch (EBaseException e) {
            logger.warn("RequestQueue: " + e.getMessage(), e);
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

    public BigInteger getLastRequestIdInRange(BigInteger reqId_low_bound, BigInteger reqId_upper_bound) {

        String method = "RequestQueue.getLastRequestIdInRange";
        logger.debug(method + ": low " + reqId_low_bound + " high " + reqId_upper_bound);
        if (reqId_low_bound == null || reqId_upper_bound == null || reqId_low_bound.compareTo(reqId_upper_bound) >= 0) {
            logger.warn(method + ": bad upper and lower bound range.");
            return null;
        }

        String filter = null;

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig config = engine.getConfig();
        String csType = null;

        try {
            csType = config.getString("cs.type");
        } catch (EBaseException e) { }

        if("KRA".equals(csType))
            filter = "(&(" + "requeststate" + "=*" + ")(!(realm=*)))";
        else
            filter = "(" + "requeststate" + "=*" + ")";

        RequestId fromId = new RequestId(reqId_upper_bound);

        logger.debug(method + ": filter " + filter + " fromId " + fromId);
        ListEnumeration recList = (ListEnumeration) getPagedRequestsByFilter(fromId, filter, 5 * -1, "requestId");

        int size = recList.getSize();

        logger.debug(method + ": size   " + size);

        int ltSize = recList.getSizeBeforeJumpTo();

        logger.debug(method +": " + ltSize);

        if (size <= 0) {
            logger.debug(method + ":  request list is empty.");

            BigInteger ret = new BigInteger(reqId_low_bound.toString(10));

            ret = ret.add(new BigInteger("-1"));

            logger.debug(method +": returning " + ret);
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

                logger.debug("RequestQueue: curReqId: " + reqId);

                BigInteger curIdInt = new BigInteger(reqId);

                if (((curIdInt.compareTo(reqId_low_bound) == 0) || (curIdInt.compareTo(reqId_low_bound) == 1)) &&
                        ((curIdInt.compareTo(reqId_upper_bound) == 0) || (curIdInt.compareTo(reqId_upper_bound) == -1))) {
                    logger.debug(method + " : returning value " + curIdInt);
                    return curIdInt;
                }

            }

        }

        BigInteger ret = new BigInteger(reqId_low_bound.toString(10));

        ret = ret.add(new BigInteger("-1"));

        logger.debug("RequestQueue:getLastRequestIdInRange: returning " + ret);
        return ret;

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

        return new SearchEnumeration(this, results);

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

        return new SearchEnumeration(this, results);
    }

    /**
     */
    public IRequestList listRequestsByFilter(String f) {
        IDBSearchResults results = null;
        DBSSession dbs = null;

        try {
            dbs = dbSubsystem.createSession();
            results = dbs.search(mBaseDN, f);
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

        return new SearchEnumeration(this, results);
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

        return new SearchEnumeration(this, results);
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

        return new SearchEnumeration(this, results);
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

        return new SearchEnumeration(this, results);
    }

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
        IDBVirtualList<IDBObj> results = null;
        DBSSession dbs = null;

        try {
            dbs = dbSubsystem.createSession();
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

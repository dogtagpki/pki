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
import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.dbs.DBSSession;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.Repository;
import com.netscape.cmscore.dbs.RepositoryRecord;
import com.netscape.cmscore.security.JssSubsystem;

/**
 * TODO: what does this class provide beyond the Repository
 * base class??
 * <p>
 *
 * @author thayes
 * @version $Revision$ $Date$
 */
public class RequestRepository extends Repository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestRepository.class);
    public static final String PROP_REQUEST_ID_GENERATOR = "request.id.generator";
    public static final String DEFAULT_REQUEST_ID_GENERATOR = "legacy";
    protected String filter;

    /**
     * Create a request repository that uses the LDAP database
     * <p>
     *
     * @param dbSubsystem
     *            the LDAP database system.
     */
    public RequestRepository(DBSubsystem dbSubsystem, String filter) throws EBaseException {

        super(dbSubsystem, 10);

        this.filter = filter;

        logger.info("RequestRepository: Initializing request repository");
        logger.info("RequestRepository: - filter: " + filter);

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        String value = dbConfig.getString(PROP_REQUEST_ID_GENERATOR, null);
        logger.debug("CertificateRepository: - cert ID generator: " + value);
        if (value != null) {
            setIDGenerator(value);
        }

        mBaseDN = dbConfig.getRequestDN() + "," + dbSubsystem.getBaseDN();
        logger.info("RequestRepository: - base DN: " + mBaseDN);

        rangeDN = dbConfig.getRequestRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.info("RequestRepository: - range DN: " + rangeDN);

        minSerialName = DBSubsystem.PROP_MIN_REQUEST_NUMBER;
        String minSerial = dbConfig.getBeginRequestNumber();
        if (minSerial != null) {
            mMinSerialNo = new BigInteger(minSerial, mRadix);
        }
        logger.info("RequestRepository: - min serial: " + mMinSerialNo);

        maxSerialName = DBSubsystem.PROP_MAX_REQUEST_NUMBER;
        String maxSerial = dbConfig.getEndRequestNumber();
        if (maxSerial != null) {
            mMaxSerialNo = new BigInteger(maxSerial, mRadix);
        }
        logger.info("RequestRepository: - max serial: " + mMaxSerialNo);

        nextMinSerialName = DBSubsystem.PROP_NEXT_MIN_REQUEST_NUMBER;
        String nextMinSerial = dbConfig.getNextBeginRequestNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = new BigInteger(nextMinSerial, mRadix);
        }
        logger.info("RequestRepository: - next min serial: " + mNextMinSerialNo);

        nextMaxSerialName = DBSubsystem.PROP_NEXT_MAX_REQUEST_NUMBER;
        String nextMaxSerial = dbConfig.getNextEndRequestNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = new BigInteger(nextMaxSerial, mRadix);
        }
        logger.info("RequestRepository: - next max serial: " + mNextMaxSerialNo);

        String lowWaterMark = dbConfig.getRequestLowWaterMark();
        if (lowWaterMark != null) {
            mLowWaterMarkNo = new BigInteger(lowWaterMark, mRadix);
        }

        String incrementNo = dbConfig.getRequestIncrement();
        if (incrementNo != null) {
            mIncrementNo = new BigInteger(incrementNo, mRadix);
        }

        // Let RequestRecord class register its
        // database mapping and object mapping values
        RequestRecord.register(dbSubsystem);
    }

    public String getNextRangeDN() {

        if (idGenerator == IDGenerator.LEGACY_2) {
            // store nextRange in range subtree for SSNv2
            return rangeDN;
        }

        // store nextRange in repository subtree for SSNv1
        return super.getNextRangeDN();
    }

    public RequestRepository(
            DBSubsystem dbSubsystem,
            String filter,
            Hashtable<String, String> repositoryConfig) throws EBaseException {

        super(dbSubsystem, 10);

        this.filter = filter;
        this.repositoryConfig = repositoryConfig;

        // Let RequestRecord class register its
        // database mapping and object mapping values
        RequestRecord.register(dbSubsystem);
    }

    public RequestId createRequestID() throws EBaseException {
        BigInteger nextSerialNumber = getNextSerialNumber();
        return new RequestId(nextSerialNumber);
    }

    public RequestId createRequestID(boolean ephemeral) throws EBaseException {

        if (!ephemeral) {
            return createRequestID();
        }

        CMSEngine engine = CMS.getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        SecureRandom random = jssSubsystem.getRandomNumberGenerator();
        long id = System.currentTimeMillis() * 10000 + random.nextInt(10000);

        return new RequestId(id);
    }

    public IRequest createRequest(RequestId requestID, String requestType) throws EBaseException {

        if (requestType == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_REQUEST_TYPE", "null"));
        }

        Request request = new Request(requestID);

        // TODO: move this to the first update. This will require
        // some state information to track the current state.
        request.setRequestType(requestType);
        request.setExtData(IRequest.REQ_VERSION, RequestQueue.REQUEST_VERSION);

        // NOT_UPDATED mean request is in memory and has not been serialized to database yet.
        // An add operation is required to serialize a NOT_UPDATED request.
        request.setExtData("dbStatus", "NOT_UPDATED");

        // expose requestId to policy so that it can be
        // used with predicate
        request.setExtData("requestId", requestID.toString());

        return request;
    }

    public IRequest createRequest(String requestType) throws EBaseException {
        RequestId requestID = createRequestID();
        return createRequest(requestID, requestType);
    }

    public void addRequest(IRequest request) throws EBaseException {

        RequestRecord requestRecord = new RequestRecord();
        requestRecord.add(request);

        DBSSession dbs = dbSubsystem.createSession();

        try {
            String dn = "cn=" + requestRecord.mRequestId + "," + mBaseDN;
            dbs.add(dn, requestRecord);

        } catch (EBaseException e) {
            logger.error("RequestRepository: " + e.getMessage(), e);
            throw e;

        } finally {
            dbs.close();
        }
    }

    public IRequest readRequest(RequestId id) throws EBaseException {

        String name = "cn=" + id + "," + mBaseDN;

        DBSSession dbs = dbSubsystem.createSession();
        RequestRecord record;

        try {
            record = (RequestRecord) dbs.read(name);

        } catch (EDBRecordNotFoundException e) {
            return null;

        } finally {
            dbs.close();
        }

        return record.toRequest();
    }

    public void modifyRequest(IRequest request) throws EBaseException {

        ModificationSet mods = new ModificationSet();
        RequestRecord.mod(mods, request);

        // mods.add(IRequestRecord.ATTR_REQUEST_STATE,
        // Modification.MOD_REPLACE, r.getRequestStatus());

        // mods.add(IRequestRecord.ATTR_SOURCE_ID,
        // Modification.MOD_REPLACE, r.getSourceId());

        // mods.add(IRequestRecord.ATTR_REQUEST_OWNER,
        // Modification.MOD_REPLACE, r.getRequestOwner());

        // mods.add(IRequestRecord.ATTR_MODIFY_TIME,
        // Modification.MOD_REPLACE, r.getModificationTime());

        // Hashtable ht = RequestRecord.loadAttrs(r);
        // mods.add(RequestRecord.ATTR_REQUEST_ATTRS, Modification.MOD_REPLACE, ht);

        DBSSession dbs = dbSubsystem.createSession();

        try {
            String dn = "cn=" + request.getRequestId() + "," + mBaseDN;
            dbs.modify(dn, mods);

        } catch (EBaseException e) {
            logger.warn("RequestRepository: " + e.getMessage(), e);
            throw e;

        } finally {
            dbs.close();
        }
    }

    /**
     * Removes all objects with this repository.
     */
    public void removeAllObjects() throws EBaseException {
        DBSSession s = dbSubsystem.createSession();
        try {
            IDBSearchResults sr = s.search(mBaseDN, "(" + RequestRecord.ATTR_REQUEST_ID + "=*)");
            while (sr.hasMoreElements()) {
                RequestRecord r = (RequestRecord) sr.nextElement();
                String name = "cn=" + r.getRequestId() + "," + mBaseDN;
                s.delete(name);
            }
        } finally {
            if (s != null)
                s.close();
        }
    }

    public IRequestList listRequestsByFilter(String filter) throws EBaseException {

        DBSSession s = dbSubsystem.createSession();
        IDBSearchResults results = null;

        try {
            results = s.search(mBaseDN, filter);

        } finally {
            s.close();
        }

        if (results == null) {
            return null;
        }

        return new SearchEnumeration(results);
    }

    public IRequestList listRequestsByFilter(String filter, int maxSize) throws EBaseException {

        DBSSession dbs = dbSubsystem.createSession();
        IDBSearchResults results = null;

        try {
            results = dbs.search(mBaseDN, filter, maxSize);

        } finally {
            dbs.close();
        }

        if (results == null) {
            return null;
        }

        return new SearchEnumeration(results);
    }

    public IRequestList listRequestsByFilter(String filter, int maxSize, int timeLimit) throws EBaseException {

        DBSSession dbs = dbSubsystem.createSession();
        IDBSearchResults results = null;

        try {
            results = dbs.search(mBaseDN, filter, maxSize, timeLimit);

        } finally {
            dbs.close();
        }

        if (results == null) {
            return null;
        }

        return new SearchEnumeration(results);
    }

    /**
     * Gets a pageable list of IRequest entries in this queue. This
     * jumps right to the end of the list.
     *
     * @param fromID request id to start with
     * @param jumpToEnd jump to end of list (set fromID to null)
     * @param filter search filter
     * @param pageSize page size
     * @param sortKey the attributes to sort by
     * @return request list
     */
    public IRequestVirtualList getPagedRequestsByFilter(
            RequestId fromID,
            boolean jumpToEnd,
            String filter,
            int pageSize,
            String sortKey) throws EBaseException {

        DBSSession session = dbSubsystem.createSession();
        IDBVirtualList<IDBObj> results;

        try {
            if (fromID == null) {
                results = session.createVirtualList(
                        mBaseDN,
                        filter,
                        (String[]) null,
                        sortKey,
                        pageSize);

            } else {
                String internalRequestID;

                if (jumpToEnd) {
                    internalRequestID = "99";
                } else {
                    int length = fromID.toString().length();
                    if (length > 9) {
                        internalRequestID = "" + length + fromID;
                    } else {
                        internalRequestID = "0" + length + fromID;
                    }
                }

                results = session.createVirtualList(
                        mBaseDN,
                        filter,
                        (String[]) null,
                        internalRequestID,
                        sortKey,
                        pageSize);
            }

        } finally {
            session.close();
        }

        results.setSortKey(sortKey);

        return new ListEnumeration(results);
    }

    @Override
    public BigInteger getLastSerialNumberInRange(BigInteger min, BigInteger max) throws EBaseException {

        logger.info("RequestRepository: Getting last serial number in range");
        logger.info("RequestRepository: - min: " + min);
        logger.info("RequestRepository: - max: " + max);

        if (min == null || max == null || min.compareTo(max) >= 0) {
            logger.warn("RequestRepository: Bad upper and lower bound range");
            return null;
        }

        RequestId fromID = new RequestId(max);
        logger.info("RequestRepository: - from ID: " + fromID);

        logger.info("RequestRepository: Searching for requests");
        ListEnumeration recList = (ListEnumeration) getPagedRequestsByFilter(
                fromID,
                false,
                filter,
                5 * -1,
                "requestId");

        int size = recList.getSize();
        logger.info("RequestRepository: - size: " + size);

        int ltSize = recList.getSizeBeforeJumpTo();
        logger.info("RequestRepository: - size before jump: " + ltSize);

        if (size <= 0) {
            BigInteger requestID = min.subtract(BigInteger.ONE);
            logger.info("RequestRepository: There are no requests, returning " + requestID);
            return requestID;
        }

        logger.info("RequestRepository: Requests:");
        for (int i = 0; i < 5; i++) {
            IRequest request = recList.getElementAt(i);

            if (request == null) {
                continue;
            }

            BigInteger requestID = request.getRequestId().toBigInteger();
            logger.info("RequestRepository: - request ID: " + requestID);

            // if request ID within range, return it
            if (requestID.compareTo(min) >= 0 && requestID.compareTo(max) <= 0) {
                logger.info("RequestRepository: Found last request ID: " + requestID);
                return requestID;
            }
        }

        BigInteger requestID = min.subtract(BigInteger.ONE);
        logger.info("RequestRepository: No request found, returning " + requestID);

        return requestID;
    }

    public String getPublishingStatus() {
        RepositoryRecord record = null;
        Object obj = null;
        DBSSession dbs = null;
        String status = null;

        try {
            dbs = dbSubsystem.createSession();
            obj = dbs.read(mBaseDN);
        } catch (Exception e) {
            logger.error("RequestRepository:  getPublishingStatus:  Error: " + e.getMessage(), e);
        } finally {
            // Close session - ignoring errors (UTIL)
            if (dbs != null) {
                try {
                    dbs.close();
                } catch (Exception ex) {
                    logger.warn("RequestRepository:  getPublishingStatus:  Error: " + ex.getMessage(), ex);
                }
            }
        }

        if (obj != null && (obj instanceof RepositoryRecord)) {
            record = (RepositoryRecord) obj;
            status = record.getPublishingStatus();
        } else {
            logger.debug("RequestRepository:  obj is NOT instanceof RepositoryRecord");
        }
        logger.debug("RequestRepository:  getPublishingStatus  mBaseDN: " + mBaseDN +
                  "  status: " + ((status != null) ? status : "null"));

        return status;
    }

    public void setPublishingStatus(String status) {
        DBSSession dbs = null;

        logger.debug("RequestRepository:  setPublishingStatus  mBaseDN: " + mBaseDN + "  status: " + status);
        ModificationSet mods = new ModificationSet();

        if (status != null && status.length() > 0) {
            mods.add(IRepositoryRecord.ATTR_PUB_STATUS,
                    Modification.MOD_REPLACE, status);

            try {
                dbs = dbSubsystem.createSession();
                dbs.modify(mBaseDN, mods);
            } catch (Exception e) {
                logger.error("RequestRepository:  setPublishingStatus:  Error: " + e.getMessage(), e);
            } finally {
                // Close session - ignoring errors (UTIL)
                if (dbs != null) {
                    try {
                        dbs.close();
                    } catch (Exception ex) {
                        logger.warn("RequestRepository:  setPublishingStatus:  Error: " + ex.getMessage(), ex);
                    }
                }
            }
        }
    }
}

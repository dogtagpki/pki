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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.DBPagedSearch;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.certsrv.dbs.DBVirtualList;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.dbs.DBSSession;
import com.netscape.cmscore.dbs.DBSearchResults;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.RecordPagedList;
import com.netscape.cmscore.dbs.Repository;
import com.netscape.cmscore.dbs.RepositoryRecord;

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
    public static final String PROP_REQUEST_ID_RADIX = "request.id.radix";
    public static final String DEFAULT_REQUEST_ID_GENERATOR = "legacy";

    public static final String PROP_REQUEST_ID_LENGTH = "request.id.length";
    public static final int DEFAULT_REQUEST_ID_LENGTH = 128;

    protected String filter;

    /**
     * Create a request repository that uses the LDAP database
     * <p>
     *
     * @param dbSubsystem
     *            the LDAP database system.
     */
    public RequestRepository(
            SecureRandom secureRandom,
            DBSubsystem dbSubsystem,
            String filter) {

        super(dbSubsystem, DEC);
        DatabaseConfig dbc = dbSubsystem.getDBConfigStore();
        try {
            this.mRadix = dbc.getInteger(PROP_REQUEST_ID_RADIX, DEC);
            logger.debug("CertificateRepository: number radix {}", this.mRadix);

        } catch (EBaseException ex) {
            logger.debug("CertificateRepository: error reading number radix config, using default {} for ", HEX);
        }
        this.secureRandom = secureRandom;
        this.filter = filter;
    }

    @Override
    public void init() throws Exception {

        logger.debug("RequestRepository: Initializing request repository");
        logger.debug("RequestRepository: - filter: " + filter);

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        mBaseDN = dbConfig.getRequestDN() + "," + dbSubsystem.getBaseDN();
        logger.debug("RequestRepository: - base DN: " + mBaseDN);

        String value = dbConfig.getString(PROP_REQUEST_ID_GENERATOR, DEFAULT_REQUEST_ID_GENERATOR);
        logger.debug("RequestRepository: - request ID generator: " + value);
        setIDGenerator(value);

        if (idGenerator == IDGenerator.RANDOM) {

            idLength = dbConfig.getInteger(PROP_REQUEST_ID_LENGTH, DEFAULT_REQUEST_ID_LENGTH);
            logger.debug("RequestRepository: - request ID length: " + idLength);
        } else if (idGenerator == IDGenerator.LEGACY_2) {
            initLegacy2Generator();
        } else {
            initLegacyGenerator();
        }

        // Let RequestRecord class register its
        // database mapping and object mapping values
        RequestRecord.register(dbSubsystem);
    }

    protected void initLegacy2Generator() throws EBaseException {
        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        rangeDN = dbConfig.getRequestRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.debug("RequestRepository: - range DN: " + rangeDN);

        mMinSerialNo = dbConfig.getBigInteger(DatabaseConfig.MIN_REQUEST_NUMBER, null);
        logger.debug("RequestRepository: - min serial: " + mMinSerialNo);

        mMaxSerialNo = dbConfig.getBigInteger(DatabaseConfig.MAX_REQUEST_NUMBER, null);
        logger.debug("RequestRepository: - max serial: " + mMaxSerialNo);

        String nextMinSerial = dbConfig.getNextBeginSerialNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = dbConfig.getBigInteger(DatabaseConfig.NEXT_MIN_REQUEST_NUMBER, null);
        }
        logger.debug("RequestRepository: - next min serial: " + mNextMinSerialNo);

        String nextMaxSerial = dbConfig.getNextEndSerialNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = dbConfig.getBigInteger(DatabaseConfig.NEXT_MAX_REQUEST_NUMBER, null);
        }
        logger.debug("RequestRepository: - next max serial: " + mNextMaxSerialNo);

        mLowWaterMarkNo = dbConfig.getBigInteger(DatabaseConfig.REQUEST_LOW_WATER_MARK, null);
        logger.debug("RequestRepository: - low water mark serial: " + mNextMaxSerialNo);

        mIncrementNo = dbConfig.getBigInteger(DatabaseConfig.REQUEST_INCREMENT, null);
        logger.debug("RequestRepository: - increment serial: " + mIncrementNo);
    }

    public void initLegacyGenerator() throws Exception {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        rangeDN = dbConfig.getRequestRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.debug("RequestRepository: - range DN: " + rangeDN);

        String minSerial = dbConfig.getBeginRequestNumber();
        if (minSerial != null) {
            mMinSerialNo = new BigInteger(minSerial, mRadix);
        }
        logger.debug("RequestRepository: - min serial: " + mMinSerialNo);

        String maxSerial = dbConfig.getEndRequestNumber();
        if (maxSerial != null) {
            mMaxSerialNo = new BigInteger(maxSerial, mRadix);
        }
        logger.debug("RequestRepository: - max serial: " + mMaxSerialNo);

        String nextMinSerial = dbConfig.getNextBeginRequestNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = new BigInteger(nextMinSerial, mRadix);
        }
        logger.debug("RequestRepository: - next min serial: " + mNextMinSerialNo);

        String nextMaxSerial = dbConfig.getNextEndRequestNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = new BigInteger(nextMaxSerial, mRadix);
        }
        logger.debug("RequestRepository: - next max serial: " + mNextMaxSerialNo);

        String lowWaterMark = dbConfig.getRequestLowWaterMark();
        if (lowWaterMark != null) {
            mLowWaterMarkNo = new BigInteger(lowWaterMark, mRadix);
        }

        String incrementNo = dbConfig.getRequestIncrement();
        if (incrementNo != null) {
            mIncrementNo = new BigInteger(incrementNo, mRadix);
        }
    }

    public String getNextRangeDN() {

        if (idGenerator == IDGenerator.LEGACY_2) {
            // store nextRange in range subtree for SSNv2
            return rangeDN;
        }

        // store nextRange in repository subtree for SSNv1
        return super.getNextRangeDN();
    }

    public void setMinSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();
        String serial = mMinSerialNo.toString(mRadix);
        if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
           serial = "0x" + serial;
        }
        logger.debug("RequestRepository: Setting min serial number: " + serial);
        dbConfig.setBeginRequestNumber(serial);
    }

    public void setMaxSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();
        String serial = mMaxSerialNo.toString(mRadix);
        if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
           serial = "0x" + serial;
        }
        logger.debug("RequestRepository: Setting max serial number: " + serial);
        dbConfig.setEndRequestNumber(serial);
    }

    public void setNextMinSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        if (mNextMinSerialNo == null) {
            logger.debug("RequestRepository: Removing next min number");
            dbConfig.removeNextBeginRequestNumber();

        } else {
            String serial = mNextMinSerialNo.toString(mRadix);
            if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
               serial = "0x" + serial;
            }
            logger.debug("RequestRepository: Setting next min number: " + serial);
            dbConfig.setNextBeginRequestNumber(serial);
        }
    }

    public void setNextMaxSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        if (mNextMaxSerialNo == null) {
            logger.debug("RequestRepository: Removing next max number");
            dbConfig.removeNextEndRequestNumber();

        } else {
            String serial = mNextMaxSerialNo.toString(mRadix);
            if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
               serial = "0x" + serial;
            }
            logger.debug("RequestRepository: Setting next max number: " + serial);
            dbConfig.setNextEndRequestNumber(serial);
        }
    }

    public void init(Hashtable<String, String> repositoryConfig) throws Exception {

        this.repositoryConfig = repositoryConfig;

        // Let RequestRecord class register its
        // database mapping and object mapping values
        RequestRecord.register(dbSubsystem);
    }

    public RequestId createRequestID() throws EBaseException {
        BigInteger nextSerialNumber = getNextSerialNumber();
        return new RequestId(nextSerialNumber);
    }

    public Request createRequest(RequestId requestID, String requestType) throws EBaseException {

        if (requestType == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_REQUEST_TYPE", "null"));
        }

        Request request = new Request(requestID);

        // TODO: move this to the first update. This will require
        // some state information to track the current state.
        request.setRequestType(requestType);
        request.setExtData(Request.REQ_VERSION, RequestQueue.REQUEST_VERSION);

        // NOT_UPDATED mean request is in memory and has not been serialized to database yet.
        // An add operation is required to serialize a NOT_UPDATED request.
        request.setExtData("dbStatus", "NOT_UPDATED");

        // expose requestId to policy so that it can be
        // used with predicate
        request.setExtData("requestId", requestID.toString());

        return request;
    }

    public Request createRequest(String requestType) throws EBaseException {
        RequestId requestID = createRequestID();
        return createRequest(requestID, requestType);
    }

    public void addRequest(Request request) throws EBaseException {

        Set<String> excludedLdapAttrs = dbSubsystem.getExcludedLdapAttr();

        RequestRecord requestRecord = new RequestRecord();
        requestRecord.add(request, excludedLdapAttrs);

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

    public Request readRequest(RequestId id) throws EBaseException {

        String name = "cn=" + id + "," + mBaseDN;

        DBSSession dbs = dbSubsystem.createSession();
        RequestRecord record;

        try {
            record = (RequestRecord) dbs.read(name);

        } catch (DBRecordNotFoundException e) {
            return null;

        } finally {
            dbs.close();
        }

        return record.toRequest();
    }

    public String getUserIdentity() {
        SessionContext s = SessionContext.getContext();
        return (String) s.get(SessionContext.USER_ID);
    }

    /**
     * Update the request in the permanent data store.
     *
     * This call can be made after changing a value like source ID or owner,
     * to force the new value to be written.
     *
     * The request must be locked to make this call.
     *
     * @param request the request that is being updated
     * @exception EBaseException failed to update request
     */
    public void updateRequest(Request request) throws EBaseException {

        String name = getUserIdentity();
        if (name != null) {
            request.setExtData(Request.UPDATED_BY, name);
        }

        String delayLDAPCommit = request.getExtDataInString("delayLDAPCommit");
        request.mModificationTime = new Date();

        if (delayLDAPCommit != null && delayLDAPCommit.equals("true")) {
            // delay writing to LDAP
            return;
        }

        // TODO: use a state flag to determine whether to call
        // addRequest or modifyRequest (see newRequest as well)

        String dbStatus = request.getExtDataInString("dbStatus");
        if (dbStatus.equals("UPDATED")) {
            modifyRequest(request);
            return;
        }

        request.setExtData("dbStatus", "UPDATED");
        addRequest(request);
    }

    public void modifyRequest(Request request) throws EBaseException {

        Set<String> excludedLdapAttrs = dbSubsystem.getExcludedLdapAttr();

        ModificationSet mods = new ModificationSet();
        RequestRecord.mod(mods, request, excludedLdapAttrs);

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
            logger.error("RequestRepository: " + e.getMessage(), e);
            throw e;

        } finally {
            dbs.close();
        }
    }

    public void removeRequest(RequestId requestID) throws EBaseException {

        DBSSession dbs = dbSubsystem.createSession();

        try {
            String name = "cn=" + requestID + "," + mBaseDN;
            dbs.delete(name);

        } catch (EBaseException e) {
            logger.error("RequestRepository: " + e.getMessage(), e);
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
            DBSearchResults sr = s.search(mBaseDN, "(" + RequestRecord.ATTR_REQUEST_ID + "=*)");
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

    /**
     * Finds a list of request records that satisfies the filter.
     *
     * The filter should follow RFC1558 LDAP filter syntax.
     * For example,
     *
     * {@Code (&(certRecordId=5)(x509Cert.notBefore=934398398))}
     *
     * @param filter search filter
     * @param timeLimit timeout value
     * @param start first entry to return from the list
     * @param size max size to return
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Iterator<RequestRecord> searchRequest(String filter, int timeLimit, int start, int size)
            throws EBaseException {

        ArrayList<RequestRecord> records = new ArrayList<>();
        logger.debug("searchRequest: filter {filter}, start {start} and size {size}", filter, start, size);
        try (DBSSession s = dbSubsystem.createSession()) {
            DBSearchResults sr  = s.pagedSearch(mBaseDN, filter, start, size, timeLimit);
            while (sr.hasMoreElements()) {
                records.add((RequestRecord) sr.nextElement());
            }
        }
        return records.iterator();
    }

    public Collection<RequestRecord> listRequestsByFilter(String filter) throws EBaseException {

        Collection<RequestRecord> records = new ArrayList<>();
        DBSSession s = dbSubsystem.createSession();

        try {
            DBSearchResults sr = s.search(mBaseDN, filter);

            while (sr.hasMoreElements()) {
                RequestRecord record = (RequestRecord) sr.nextElement();
                records.add(record);
            }

        } finally {
            s.close();
        }

        return records;
    }

    public Collection<RequestRecord> listRequestsByFilter(String filter, int maxSize) throws EBaseException {

        Collection<RequestRecord> records = new ArrayList<>();
        DBSSession dbs = dbSubsystem.createSession();

        try {
            DBSearchResults sr = dbs.search(mBaseDN, filter, maxSize);

            while (sr.hasMoreElements()) {
                RequestRecord record = (RequestRecord) sr.nextElement();
                records.add(record);
            }

        } finally {
            dbs.close();
        }

        return records;
    }

    public Collection<RequestRecord> listRequestsByFilter(String filter, int maxSize, int timeLimit) throws EBaseException {

        Collection<RequestRecord> records = new ArrayList<>();
        DBSSession dbs = dbSubsystem.createSession();

        try {
            DBSearchResults sr = dbs.search(mBaseDN, filter, maxSize, timeLimit);

            while (sr.hasMoreElements()) {
                RequestRecord record = (RequestRecord) sr.nextElement();
                records.add(record);
            }

        } finally {
            dbs.close();
        }

        return records;
    }

    /**
     * Gets a paginated list of Request entries in this queue.
     *
     * @param toID request id to end with
     * @param filter search filter
     * @param pageSize page size
     * @param sortKey the attributes to sort by
     * @return request list
     */
    public RecordPagedList<RequestRecord> getPagedRequestsByFilter(
            RequestId toID,
            String filter,
            int pageSize,
            String sortKey) throws EBaseException {
        if (toID != null) {
            if(!filter.startsWith("(")) {
                filter = "(" + filter + ")";
            }
            filter = "(& (requestID <= " + toID + ")" + filter +")";
        }
        return getPagedRequestsByFilter(filter, pageSize, sortKey);
    }

    /**
     * Gets a paginated list of Request entries in this queue.
     *
     * @param filter search filter
     * @param pageSize page size
     * @param sortKey the attributes to sort by
     * @return request list
     */
    public RecordPagedList<RequestRecord> getPagedRequestsByFilter(
            String filter,
            int pageSize,
            String sortKey) throws EBaseException {
        try(DBSSession session = dbSubsystem.createSession()){
            DBPagedSearch<RequestRecord> pages;
            pages = session.createPagedSearch(RequestRecord.class, mBaseDN, filter, null, sortKey);
            return new RecordPagedList<>(pages);
        }
    }

    /**
     * Gets the total number of request entries.
     *
     * @param filter search filter
     * @return number of entries
     */
    public int getTotalRequestsByFilter(
            String filter) throws EBaseException {
        try(DBSSession session = dbSubsystem.createSession()){
            return session.countEntries(RequestRecord.class, mBaseDN, filter, -1);
        }
    }
    /**
     * Gets a pageable list of Request entries in this queue. This
     * jumps right to the end of the list.
     *
     * @param fromID request id to start with
     * @param jumpToEnd jump to end of list (set fromID to null)
     * @param filter search filter
     * @param pageSize page size
     * @param sortKey the attributes to sort by
     * @return request list
     * @deprecated As of release 11.6.0
     */
    @Deprecated(since = "11.6.0", forRemoval = true)
    public IRequestVirtualList getPagedRequestsByFilter(
            RequestId fromID,
            boolean jumpToEnd,
            String filter,
            int pageSize,
            String sortKey) throws EBaseException {

        DBSSession session = dbSubsystem.createSession();
        DBVirtualList<IDBObj> results;

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

        logger.debug("RequestRepository: Getting last serial number in range");
        logger.debug("RequestRepository: - min: {}", min);
        logger.debug("RequestRepository: - max: {}", max);

        if (min == null || max == null || min.compareTo(max) >= 0) {
            logger.warn("RequestRepository: Bad upper and lower bound range");
            return null;
        }

        RequestId toID = new RequestId(max);
        logger.debug("RequestRepository: - to ID: {}", toID);


        logger.debug("RequestRepository: Searching for requests");
        RecordPagedList<RequestRecord> reqRecords = getPagedRequestsByFilter(
                toID,
                filter, 5,
                "-requestId");
        Iterator<RequestRecord> iReqs = reqRecords.iterator();

        logger.debug("RequestRepository: Requests:");
        if (iReqs.hasNext()) {
            RequestRecord recReq = iReqs.next();
            Request request = recReq.toRequest();

            if (request != null) {
                BigInteger requestID = request.getRequestId().toBigInteger();
                logger.debug("RequestRepository: - request ID: {}", requestID);

                // if request ID within range, return it
                if (requestID.compareTo(min) >= 0) {
                    logger.debug("RequestRepository: Found last request ID: {}", requestID);
                    return requestID;
                }
            }
        }

        BigInteger requestID = min.subtract(BigInteger.ONE);
        logger.debug("RequestRepository: No request found, returning {}", requestID);

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
            mods.add(RepositoryRecord.ATTR_PUB_STATUS,
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

    /**
     * Locates all requests with a particular SourceId.
     *
     * @param id an identifier for the record that is based on the source
     *  of the request
     * @return A list of requests corresponding to this source id. null is
     *  returned if the source id does not exist.
     */
    public Collection<RequestRecord> findRequestsBySourceId(String id) throws EBaseException {
        String filter = "(" + RequestRecord.ATTR_SOURCE_ID + "=" + id + ")";
        return listRequestsByFilter(filter);
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
        Collection<RequestRecord> records = findRequestsBySourceId(id);

        if (records.isEmpty())
            return null;

        RequestRecord record = records.iterator().next();
        return record.getRequestId();
    }
}

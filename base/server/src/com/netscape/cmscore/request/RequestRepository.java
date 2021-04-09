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
import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.dbs.DBSSession;
import com.netscape.cmscore.dbs.DBSubsystem;
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

    ARequestQueue mRequestQueue = null;

    /**
     * Create a request repository that uses the LDAP database
     * <p>
     *
     * @param dbSubsystem
     *            the LDAP database system.
     */
    public RequestRepository(DBSubsystem dbSubsystem) throws EBaseException {

        super(dbSubsystem, 10);

        logger.info("RequestRepository: Initializing request repository");

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

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

    public RequestRepository(
            DBSubsystem dbSubsystem,
            Hashtable<String, String> repositoryConfig) throws EBaseException {

        super(dbSubsystem, 10);

        this.repositoryConfig = repositoryConfig;

        // Let RequestRecord class register its
        // database mapping and object mapping values
        RequestRecord.register(dbSubsystem);
    }

    public void setRequestQueue(ARequestQueue requestQueue) {
        this.mRequestQueue = requestQueue;
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
                String name = "cn" + "=" +
                        r.getRequestId().toString() + "," + getBaseDN();
                s.delete(name);
            }
        } finally {
            if (s != null)
                s.close();
        }
    }

    public BigInteger getLastSerialNumberInRange(BigInteger min, BigInteger max) throws EBaseException {

        logger.info("RequestRepository: Getting last serial number in range");
        logger.info("RequestRepository: - min: " + min);
        logger.info("RequestRepository: - max: " + max);

        if (min == null || max == null || min.compareTo(max) >= 0) {
            logger.warn("RequestRepository: Bad upper and lower bound range");
            return null;
        }

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig config = engine.getConfig();
        String csType = config.getString("cs.type");

        String filter = null;
        if("KRA".equals(csType)) {
            filter = "(&(" + "requeststate" + "=*" + ")(!(realm=*)))";
        } else {
            filter = "(" + "requeststate" + "=*" + ")";
        }
        logger.info("RequestRepository: - filter: " + filter);

        RequestId fromID = new RequestId(max);
        logger.info("RequestRepository: - from ID: " + fromID);

        logger.info("RequestRepository: Searching for requests");
        ListEnumeration recList = (ListEnumeration) mRequestQueue.getPagedRequestsByFilter(
                fromID,
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

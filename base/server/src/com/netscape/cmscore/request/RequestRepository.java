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
import com.netscape.cmscore.apps.DatabaseConfig;
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
    public RequestRepository(DBSubsystem dbSubsystem, int increment) throws EBaseException {

        super(
                dbSubsystem,
                increment,
                10);

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

        repositoryConfig.put(DBSubsystem.PROP_INCREMENT_NAME, DBSubsystem.PROP_REQUEST_INCREMENT);
        repositoryConfig.put(DBSubsystem.PROP_INCREMENT, dbConfig.getRequestIncrement());

        // Let RequestRecord class register its
        // database mapping and object mapping values
        RequestRecord.register(dbSubsystem);
    }

    public RequestRepository(
            DBSubsystem dbSubsystem,
            int increment,
            Hashtable<String, String> repositoryConfig) throws EBaseException {

        super(
                dbSubsystem,
                increment,
                10);

        this.repositoryConfig = repositoryConfig;

        // Let RequestRecord class register its
        // database mapping and object mapping values
        RequestRecord.register(dbSubsystem);
    }

    public void setRequestQueue(ARequestQueue requestQueue) {
        this.mRequestQueue = requestQueue;
    }

    /**
     * Resets serial number.
     */
    public void resetSerialNumber(BigInteger serial) throws EBaseException {
        setTheSerialNumber(serial);
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

    public BigInteger getLastSerialNumberInRange(BigInteger min, BigInteger max) {

        logger.debug("RequestRepository: in getLastSerialNumberInRange: min " + min + " max " + max);

        logger.debug("RequestRepository: mRequestQueue " + mRequestQueue);

        BigInteger ret = null;

        if (mRequestQueue == null) {

            logger.warn("RequestRepository:  mRequestQueue is null.");

        } else {

            logger.debug("RequestRepository: about to call mRequestQueue.getLastRequestIdInRange");
            ret = mRequestQueue.getLastRequestIdInRange(min, max);

        }

        return ret;

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

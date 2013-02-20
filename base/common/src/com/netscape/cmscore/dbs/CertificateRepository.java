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
package com.netscape.cmscore.dbs;


import java.math.BigInteger;
import java.util.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import netscape.security.x509.*;
import netscape.ldap.*;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.dbs.repository.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.ca.*;

import com.netscape.cmscore.dbs.*;
import com.netscape.cmscore.util.*;
import com.netscape.cmscore.cert.*;


/**
 * A class represents a certificate repository. It
 * stores all the issued certificate.
 * <P>
 *
 * @author thomask
 * @author kanda
 * @version $Revision$, $Date$
 */
public class CertificateRepository extends Repository
    implements ICertificateRepository {

    private static final String PROP_ENABLE_RANDOM_SERIAL_NUMBERS = "enableRandomSerialNumbers";
    private static final String PROP_RANDOM_SERIAL_NUMBER_COUNTER = "randomSerialNumberCounter";
    private static final String PROP_FORCE_MODE_CHANGE = "forceModeChange";
    private static final String PROP_RANDOM_MODE = "random";
    private static final String PROP_SEQUENTIAL_MODE = "sequential";
    private static final String PROP_COLLISION_RECOVERY_STEPS = "collisionRecoverySteps";
    private static final String PROP_COLLISION_RECOVERY_REGENERATIONS = "collisionRecoveryRegenerations";
    private static final BigInteger BI_MINUS_ONE = (BigInteger.ZERO).subtract(BigInteger.ONE);
    private final int REPLICA_BITS = 16;

    private IDBSubsystem mDBService;
    private String mBaseDN;
    private String mRequestBaseDN;
    private boolean mConsistencyCheck = false;
    private boolean mSkipIfInconsistent = false;

    private int mCertStatusUpdateInterval = 0;
    private Hashtable mCRLIssuingPoints = new Hashtable();

    private int mTransitMaxRecords = 1000000;
    private int mTransitRecordPageSize = 200;

    private Random mRandom = null;
    private int mBitLength = 0;
    private BigInteger mRangeSize = null;
    private BigInteger mRandomRangeSize = null;
    private BigInteger mReplicaID = null;
    private int mMinRandomBitLength = 4;
    private int mReplicaBitLength = REPLICA_BITS;
    private int mMaxCollisionRecoverySteps = 10;
    private int mMaxCollisionRecoveryRegenerations = 3;
    private IConfigStore mDBConfig = null;
    private boolean mForceModeChange = false;

    /**
     * Constructs a certificate repository.
     */
    public CertificateRepository(IDBSubsystem dbService, String certRepoBaseDN, int increment, String baseDN)
        throws EDBException {
        super(dbService, increment, baseDN);
        mBaseDN = certRepoBaseDN;
      
        mDBService = dbService;
        mDBConfig = mDBService.getDBConfigStore();
    }

    public ICertRecord createCertRecord(BigInteger id, Certificate cert, MetaInfo meta) {
        return new CertRecord(id, cert, meta);
    }

    public boolean getEnableRandomSerialNumbers() {
        return mEnableRandomSerialNumbers;
    }

    public void setEnableRandomSerialNumbers(boolean random, boolean updateMode) {
        if (mEnableRandomSerialNumbers ^ random) {
            mEnableRandomSerialNumbers = random;
            CMS.debug("CertificateRepository:  setEnableRandomSerialNumbers   switching to " +
                      ((random)?PROP_RANDOM_MODE:PROP_SEQUENTIAL_MODE) + " mode");
            if (updateMode) {
                setCertificateRepositoryMode((mEnableRandomSerialNumbers)? PROP_RANDOM_MODE: PROP_SEQUENTIAL_MODE);
            }
            mDBConfig.putBoolean(PROP_ENABLE_RANDOM_SERIAL_NUMBERS, mEnableRandomSerialNumbers);

            BigInteger lastSerialNumber = null;
            try {
                lastSerialNumber = getLastSerialNumberInRange(mMinSerialNo,mMaxSerialNo);
            } catch (Exception e) {
            }
            if (lastSerialNumber != null) {
                super.setLastSerialNo(lastSerialNumber);
                if (mEnableRandomSerialNumbers) {
                    mCounter = lastSerialNumber.subtract(mMinSerialNo).add(BigInteger.ONE);
                    CMS.debug("CertificateRepository:  setEnableRandomSerialNumbers  mCounter="+
                               mCounter+"="+lastSerialNumber+"-"+mMinSerialNo+"+1");
                    long t = System.currentTimeMillis();
                    mDBConfig.putString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, mCounter.toString()+","+t);
                } else {
                    mCounter = BI_MINUS_ONE;
                    mDBConfig.putString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, mCounter.toString());
                }
            }

            try {
                CMS.getConfigStore().commit(false);
            } catch (Exception e) {
            }
        }
    }

    private BigInteger getRandomNumber() throws EBaseException {
        BigInteger randomNumber = null;

        if (mRandom == null) {
            mRandom = new Random();
        }
        super.initCacheIfNeeded();

        if (mRangeSize == null || mReplicaID == null) {
            mRangeSize = (mMaxSerialNo.subtract(mMinSerialNo)).add(BigInteger.ONE);
            mBitLength = mRangeSize.bitLength();
            int rid = mDBService.getReplicaID();
            rid = -1;  // shared ranges using replica IDs are postponed
            if (rid > -1) {
                mReplicaID = new BigInteger((new Integer(rid)).toString());
            } else {
                mReplicaBitLength = 0;
            }
            mRandomRangeSize = mRangeSize.shiftRight(mReplicaBitLength);
        }
        if (mBitLength - mReplicaBitLength < mMinRandomBitLength) {
            CMS.debug("CertificateRepository: getRandomNumber:  Range size is too small to support random certificate serial numbers.");
            throw new EBaseException ("Range size is too small to support random certificate serial numbers.");
        }
        randomNumber = new BigInteger((mBitLength-mReplicaBitLength), mRandom);
        randomNumber = (randomNumber.multiply(mRandomRangeSize)).shiftRight(mBitLength-mReplicaBitLength);
        CMS.debug("CertificateRepository: getRandomNumber  randomNumber="+randomNumber);

        return randomNumber; 
    }

    private BigInteger getRandomSerialNumber(BigInteger randomNumber) throws EBaseException {
        BigInteger nextSerialNumber = null;

        if (mReplicaBitLength > 0) {
            nextSerialNumber = (randomNumber.shiftLeft(mReplicaBitLength)).add(mReplicaID);
        } else {
            nextSerialNumber = randomNumber;
        }
        nextSerialNumber = (nextSerialNumber.add(mMinSerialNo)).subtract(BigInteger.ONE);
        CMS.debug("CertificateRepository: getRandomSerialNumber  nextSerialNumber="+nextSerialNumber);

        return nextSerialNumber; 
    }

    private BigInteger checkSerialNumbers(BigInteger randomNumber, BigInteger serialNumber) throws EBaseException {
        BigInteger nextSerialNumber = null;
        BigInteger initialRandomNumber = randomNumber;
        BigInteger delta = BigInteger.ZERO;
        int i = 0;
        int n = mMaxCollisionRecoverySteps;

        do {
            CMS.debug("CertificateRepository: checkSerialNumbers  checking("+(i+1)+")="+serialNumber);
            try {
                if (readCertificateRecord(serialNumber) != null) {
                    CMS.debug("CertificateRepository: checkSerialNumbers  collision detected for serialNumber="+serialNumber);
                }
            } catch (EDBRecordNotFoundException nfe) {
                CMS.debug("CertificateRepository: checkSerialNumbers  serial number "+serialNumber+" is available");
                nextSerialNumber = serialNumber;
            } catch (Exception e) {
                CMS.debug("CertificateRepository: checkSerialNumbers  Exception="+e.getMessage());
            }

            if (nextSerialNumber == null) {
                if (i%2 == 0) {
                    delta = delta.add(BigInteger.ONE);
                    serialNumber = getRandomSerialNumber(initialRandomNumber.add(delta));

                    if (mMaxSerialNo != null && serialNumber.compareTo(mMaxSerialNo) > 0) {
                        serialNumber = getRandomSerialNumber(initialRandomNumber.subtract(delta));
                        i++;
                        n++;
                    }
                } else {
                    serialNumber = getRandomSerialNumber(initialRandomNumber.subtract(delta));
                    if (mMinSerialNo != null && serialNumber.compareTo(mMinSerialNo) < 0) {
                        delta = delta.add(BigInteger.ONE);
                        serialNumber = getRandomSerialNumber(initialRandomNumber.add(delta));
                        i++;
                        n++;
                    }
                }
                i++;
            }
        } while (nextSerialNumber == null && i < n);

        return nextSerialNumber; 
    }

    private Object nextSerialNumberMonitor = new Object();

    public BigInteger getNextSerialNumber() throws
            EBaseException {

        BigInteger nextSerialNumber = null;
        BigInteger randomNumber = null;

        synchronized (nextSerialNumberMonitor) {
            CMS.debug("CertificateRepository: getNextSerialNumber  mEnableRandomSerialNumbers="+mEnableRandomSerialNumbers);

            if (mEnableRandomSerialNumbers) {
                int i = 0;
                do {
                    if (i > 0) {
                        CMS.debug("CertificateRepository: getNextSerialNumber  regenerating serial number");
                    }
                    randomNumber = getRandomNumber();
                    nextSerialNumber = getRandomSerialNumber(randomNumber);
                    nextSerialNumber = checkSerialNumbers(randomNumber, nextSerialNumber);
                    i++;
                } while (nextSerialNumber == null && i < mMaxCollisionRecoveryRegenerations);

                if (nextSerialNumber == null) {
                    CMS.debug("CertificateRepository: in getNextSerialNumber  nextSerialNumber is null");
                    throw new EBaseException( "nextSerialNumber is null" );
                }

                if (mCounter.compareTo(BigInteger.ZERO) >= 0 &&
                    mMinSerialNo != null && mMaxSerialNo != null &&
                    nextSerialNumber != null &&
                    nextSerialNumber.compareTo(mMinSerialNo) >= 0 &&
                    nextSerialNumber.compareTo(mMaxSerialNo) <= 0) {
                    mCounter = mCounter.add(BigInteger.ONE);
                }
                CMS.debug("CertificateRepository: getNextSerialNumber  nextSerialNumber="+
                          nextSerialNumber+"  mCounter="+mCounter);

                super.checkRange();
            } else {
                nextSerialNumber = super.getNextSerialNumber();
            }
        }

        return nextSerialNumber; 
    }

    private void updateCounter() {
        CMS.debug("CertificateRepository: updateCounter  mEnableRandomSerialNumbers="+
                  mEnableRandomSerialNumbers+"  mCounter="+mCounter);
        try {
            super.initCacheIfNeeded();
        } catch (Exception e) {
            CMS.debug("CertificateRepository: updateCounter  Exception from initCacheIfNeeded: "+e.getMessage());
        }

        String crMode = mDBService.getEntryAttribute(mBaseDN, IRepositoryRecord.ATTR_DESCRIPTION, "", null);

        boolean modeChange = (mEnableRandomSerialNumbers && crMode != null && crMode.equals(PROP_SEQUENTIAL_MODE)) ||
                             ((!mEnableRandomSerialNumbers) && crMode != null && crMode.equals(PROP_RANDOM_MODE));
        CMS.debug("CertificateRepository: updateCounter  modeChange="+modeChange);
        if (modeChange) {
            if (mForceModeChange) {
                setEnableRandomSerialNumbers(mEnableRandomSerialNumbers, true);
            } else {
                setEnableRandomSerialNumbers(!mEnableRandomSerialNumbers, false);
            }
        } else if (mEnableRandomSerialNumbers && mCounter != null &&
                   mCounter.compareTo(BigInteger.ZERO) >= 0) {
            long t = System.currentTimeMillis();
            mDBConfig.putString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, mCounter.toString()+","+t);
            try {
                CMS.getConfigStore().commit(false);
            } catch (Exception e) {
                CMS.debug("CertificateRepository: updateCounter  Exception committing ConfigStore="+e.getMessage());
            }
        }
        CMS.debug("CertificateRepository: UpdateCounter  mEnableRandomSerialNumbers="+
                  mEnableRandomSerialNumbers+"  mCounter="+mCounter);
    }

    private BigInteger getInRangeCount(String fromTime, BigInteger  minSerialNo, BigInteger maxSerialNo)
    throws EBaseException {
        BigInteger count = BigInteger.ZERO;
        String filter = null;

        if (fromTime != null && fromTime.length() > 0) {
            filter = "(certCreateTime >= "+fromTime+")";
        } else {
            filter = "(&("+ICertRecord.ATTR_ID+">="+minSerialNo+")("+
                           ICertRecord.ATTR_ID+"<="+maxSerialNo+"))";
        }
        CMS.debug("CertificateRepository: getInRangeCount  filter="+filter+
                  "  minSerialNo="+minSerialNo+"  maxSerialNo="+maxSerialNo);

        Enumeration e = findCertRecs(filter, new String[] {ICertRecord.ATTR_ID, "objectclass"});
        while (e != null && e.hasMoreElements()) {
            ICertRecord rec = (ICertRecord) e.nextElement();
            if (rec != null) {
                BigInteger sn = rec.getSerialNumber();
                if (fromTime == null || fromTime.length() == 0 ||
                    (minSerialNo != null && maxSerialNo != null &&
                     sn != null && sn.compareTo(minSerialNo) >= 0 &&
                     sn.compareTo(maxSerialNo) <= 0)) {
                    count = count.add(BigInteger.ONE);
                }
            }
        }
        CMS.debug("CertificateRepository: getInRangeCount  count=" + count);

        return count; 
    }

    private BigInteger getInRangeCounter(BigInteger  minSerialNo, BigInteger maxSerialNo)
    throws EBaseException {
        String c = null;
        String t = null;
        String s = (mDBConfig.getString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, "-1")).trim();
        CMS.debug("CertificateRepository: getInRangeCounter:  saved counter string="+s);
        int i = s.indexOf(',');
        int n = s.length();
        if (i > -1) {
            if (i > 0) {
                c = s.substring(0, i);
                if (i < n) {
                    t = s.substring(i+1);
                }
            } else {
                c = "-1";
            }
        } else {
            c = s;
        }
        CMS.debug("CertificateRepository: getInRangeCounter:  c=" + c + ((t != null)?("  t="+t):""));

        BigInteger counter = new BigInteger(c);
        BigInteger count = BigInteger.ZERO;
        if (t != null) {
            count = getInRangeCount(t, minSerialNo, maxSerialNo);
            if (count.compareTo(BigInteger.ZERO) > 0) {
                counter = counter.add(count);
            }
        } else if (s.equals("-2")) {
            count = getInRangeCount(t, minSerialNo, maxSerialNo);
            if (count.compareTo(BigInteger.ZERO) >= 0) {
                counter = count;
            }
        }
        CMS.debug("CertificateRepository: getInRangeCounter:  counter=" + counter);

        return counter; 
    }

    public BigInteger getLastSerialNumberInRange(BigInteger  serial_low_bound, BigInteger serial_upper_bound)
    throws EBaseException {

        CMS.debug("CertificateRepository:  in getLastSerialNumberInRange: low " + serial_low_bound + " high " + serial_upper_bound);

        if(serial_low_bound == null || serial_upper_bound == null || serial_low_bound.compareTo(serial_upper_bound) >= 0 )
        { 
            return null;

        }

        mEnableRandomSerialNumbers = mDBConfig.getBoolean(PROP_ENABLE_RANDOM_SERIAL_NUMBERS, false);
        mForceModeChange = mDBConfig.getBoolean(PROP_FORCE_MODE_CHANGE, false);
        String crMode = mDBService.getEntryAttribute(mBaseDN, IRepositoryRecord.ATTR_DESCRIPTION, "", null);
        mMaxCollisionRecoverySteps = mDBConfig.getInteger(PROP_COLLISION_RECOVERY_STEPS, 10);
        mMaxCollisionRecoveryRegenerations = mDBConfig.getInteger(PROP_COLLISION_RECOVERY_REGENERATIONS, 3);
        boolean modeChange = (mEnableRandomSerialNumbers && crMode != null && crMode.equals(PROP_SEQUENTIAL_MODE)) ||
                             ((!mEnableRandomSerialNumbers) && crMode != null && crMode.equals(PROP_RANDOM_MODE));
        CMS.debug("CertificateRepository: getLastSerialNumberInRange"+
                  "  mEnableRandomSerialNumbers="+mEnableRandomSerialNumbers+
                  "  CollisionRecovery="+mMaxCollisionRecoveryRegenerations+","+mMaxCollisionRecoverySteps);
        CMS.debug("CertificateRepository: getLastSerialNumberInRange  modeChange="+modeChange+
                  "  mForceModeChange="+mForceModeChange+((crMode != null)?("  mode="+crMode):""));
        if (modeChange) {
            if (mForceModeChange) {
                setCertificateRepositoryMode((mEnableRandomSerialNumbers)? PROP_RANDOM_MODE: PROP_SEQUENTIAL_MODE);
                mForceModeChange = false;
                mDBConfig.remove(PROP_FORCE_MODE_CHANGE);
            } else {
                mEnableRandomSerialNumbers = !mEnableRandomSerialNumbers;
                mDBConfig.putBoolean(PROP_ENABLE_RANDOM_SERIAL_NUMBERS, mEnableRandomSerialNumbers);
            }
        }  
        if (mEnableRandomSerialNumbers && mCounter == null) {
            mCounter = getInRangeCounter(serial_low_bound, serial_upper_bound);
        } else {
            mCounter = BI_MINUS_ONE;
        }
        mDBConfig.putString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, mCounter.toString());
        try {
            CMS.getConfigStore().commit(false);
        } catch (Exception e) {
        }
        CMS.debug("CertificateRepository: getLastSerialNumberInRange  mEnableRandomSerialNumbers="+mEnableRandomSerialNumbers);

        String ldapfilter = "("+ICertRecord.ATTR_CERT_STATUS+"=*"+")";

        String[] attrs = null;

        ICertRecordList recList = findCertRecordsInList(ldapfilter,attrs,serial_upper_bound.toString(10),"serialno", 5 * -1);

        int size = recList.getSize();

        CMS.debug("CertificateRepository:getLastSerialNumberInRange: recList size " + size);

        if (size <= 0) {
            CMS.debug("CertificateRepository:getLastSerialNumberInRange: index may be empty");

            BigInteger ret = new BigInteger(serial_low_bound.toString(10));

            ret = ret.subtract(BigInteger.ONE); 
            CMS.debug("CertificateRepository:getLastCertRecordSerialNo: returning " + ret);
            return ret;
        }
        int ltSize = recList.getSizeBeforeJumpTo();

        Vector cList = new Vector(ltSize);

        CMS.debug("CertificateRepository:getLastSerialNumberInRange: ltSize " + ltSize);

        CertRecord curRec = null;

        int i;
        Object obj = null;

        for (i = 0; i < 5; i++) {
            obj = recList.getCertRecord(i);

            if (obj != null) {
                curRec = (CertRecord) obj;

                BigInteger serial = curRec.getSerialNumber();

                CMS.debug("CertificateRepository:getLastCertRecordSerialNo:  serialno  " + serial);

                if(  ((serial.compareTo(serial_low_bound) == 0) || (serial.compareTo(serial_low_bound) == 1) ) &&
                     ((serial.compareTo(serial_upper_bound) == 0) || (serial.compareTo(serial_upper_bound) == -1) ))
                {
                    CMS.debug("getLastSerialNumberInRange returning: " + serial);
                    return serial;
                }
            } else {
                CMS.debug("getLastSerialNumberInRange:found null from getCertRecord");
            }
        }
        

        BigInteger ret = new BigInteger(serial_low_bound.toString(10));

        ret = ret.subtract(BigInteger.ONE); 

        CMS.debug("CertificateRepository:getLastCertRecordSerialNo: returning " + ret);
        return ret; 

    }

    /**
     * Removes all objects with this repository.
     */
    public void removeCertRecords(BigInteger beginS, BigInteger endS) throws EBaseException
    {
        String filter = "(" + CertRecord.ATTR_CERT_STATUS + "=*" + ")";
        ICertRecordList list =findCertRecordsInList(filter, 
                    null, "serialno", 10);
        int size = list.getSize();
        Enumeration e = list.getCertRecords(0, size - 1);
        while (e.hasMoreElements()) {
            CertRecord rec = (CertRecord) e.nextElement();
            BigInteger cur = rec.getSerialNumber();
            BigInteger max = cur.max(beginS);
            BigInteger min = cur;
            if (endS != null)
                min = cur.min(endS);
            if (cur.equals(beginS) || cur.equals(endS) || 
              (cur.equals(max) && cur.equals(min)))
                deleteCertificateRecord(cur);
        }
    }

    public void setConsistencyCheck(boolean ConsistencyCheck) {
        mConsistencyCheck = ConsistencyCheck;
    }

    public void setSkipIfInConsistent(boolean SkipIfInconsistent) {
        mSkipIfInconsistent = SkipIfInconsistent;
    }

    public void setTransitMaxRecords(int max) {
        mTransitMaxRecords = max;
    }

    public void setTransitRecordPageSize(int size) {
        mTransitRecordPageSize = size;

    }

    /**
     * register CRL Issuing Point
     */
    public void addCRLIssuingPoint(String id, ICRLIssuingPoint crlIssuingPoint) {
        mCRLIssuingPoints.put(id, crlIssuingPoint);
    }

    /**
     * interval value: (in seconds)
     *   0 - disable
     *   >0 - enable
     */
    public CertStatusUpdateThread mCertStatusUpdateThread = null;
    public RetrieveModificationsThread mRetrieveModificationsThread = null;

    public void setCertStatusUpdateInterval(IRepository requestRepo, int interval, boolean listenToCloneModifications) {
        CMS.debug("In setCertStatusUpdateInterval " + interval);
        if (interval == 0) {
            CMS.debug("In setCertStatusUpdateInterval interval = 0" + interval);
            if (mCertStatusUpdateThread != null) {
                mCertStatusUpdateThread.stop();
            }
            if (mRetrieveModificationsThread != null) {
                mRetrieveModificationsThread.stop();
            }
            return;
        }

        CMS.debug("In setCertStatusUpdateInterval  listenToCloneModifications="+listenToCloneModifications+
                  "  mRetrieveModificationsThread="+mRetrieveModificationsThread);
        if (listenToCloneModifications && mRetrieveModificationsThread == null) {
            CMS.debug("In setCertStatusUpdateInterval about to create RetrieveModificationsThread");
            mRetrieveModificationsThread = new RetrieveModificationsThread(this, "RetrieveModificationsThread");
            LDAPSearchResults mResults = null;
            try {
                mResults = startSearchForModifiedCertificateRecords();
            } catch (Exception e) {
                mResults = null;
            }
            if (mResults != null) {
                mRetrieveModificationsThread.setResults(mResults);
                mRetrieveModificationsThread.start();
            }
        }

        CMS.debug("In setCertStatusUpdateInterval  mCertStatusUpdateThread " + mCertStatusUpdateThread);
        if (mCertStatusUpdateThread == null) {
            CMS.debug("In setCertStatusUpdateInterval about to create CertStatusUpdateThread ");
            mCertStatusUpdateThread = new CertStatusUpdateThread(this, requestRepo, "CertStatusUpdateThread");
            mCertStatusUpdateThread.setInterval(interval);
            mCertStatusUpdateThread.start();
        } else {
            CMS.debug("In setCertStatusUpdateInterval it thinks the thread is up already ");
            mCertStatusUpdateThread.setInterval(interval);
            // dont do anything if we have a thread running already
        }
    }


    /**
     * Blocking method.
     */
    public void updateCertStatus() throws EBaseException {

        CMS.debug("In updateCertStatus()");

        CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER, 
            CMS.getLogMessage("CMSCORE_DBS_START_VALID_SEARCH"));
        transitInvalidCertificates();
        CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
            CMS.getLogMessage("CMSCORE_DBS_FINISH_VALID_SEARCH"));
        CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
            CMS.getLogMessage("CMSCORE_DBS_START_EXPIRED_SEARCH"));
        transitValidCertificates();
        CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
            CMS.getLogMessage("CMSCORE_DBS_FINISH_EXPIRED_SEARCH"));
        CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
            CMS.getLogMessage("CMSCORE_DBS_START_REVOKED_EXPIRED_SEARCH"));
        transitRevokedExpiredCertificates();
        CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
            CMS.getLogMessage("CMSCORE_DBS_FINISH_REVOKED_EXPIRED_SEARCH"));
        updateCounter();
    }

    /**
     * Retrieves DN of this repository.
     */
    public String getDN() {
        return mBaseDN;
    }

    public void setRequestDN( String requestDN )  {
        mRequestBaseDN = requestDN;
    }

    public String getRequestDN()  {
        return mRequestBaseDN;
    }
    /**
     * Retrieves backend database handle.
     */
    public IDBSubsystem getDBSubsystem() {
        return mDBService;
    }

    /**
     * Adds a certificate record to the repository. Each certificate
     * record contains four parts: certificate, meta-attributes,
     * issue information and reovcation information.
     * <P>
     *
     * @param cert X.509 certificate
     * @exception EBaseException failed to add new certificate to
     * 		the repository
     */
    public void addCertificateRecord(ICertRecord record)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();

        try {
            String name = "cn" + "=" +
                ((CertRecord) record).getSerialNumber().toString() + "," + getDN();
            SessionContext ctx = SessionContext.getContext();
            String uid = (String) ctx.get(SessionContext.USER_ID);

            if (uid == null) {
                // XXX is this right?
                record.set(CertRecord.ATTR_ISSUED_BY, "system");

                /**
                 System.out.println("XXX servlet should set USER_ID");
                 throw new EBaseException(BaseResources.UNKNOWN_PRINCIPAL_1, 
                 "null");
                 **/
            } else {
                record.set(CertRecord.ATTR_ISSUED_BY, uid);
            }

            // Check validity of this certificate. If it is not invalid, 
            // mark it so. We will have a thread to transit the status
            // from INVALID to VALID.
            X509CertImpl x509cert = (X509CertImpl) record.get(
                    CertRecord.ATTR_X509CERT);

            if (x509cert != null) {
                Date now = CMS.getCurrentDate();

                if (x509cert.getNotBefore().after(now)) {
                    // not yet valid
                    record.set(ICertRecord.ATTR_CERT_STATUS, 
                        ICertRecord.STATUS_INVALID);
                }
            }
			
            s.add(name, record);
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Used by the Clone Master (CLA) to add a revoked certificate
     * record to the repository.
     * <p>
     *
     * @param record a CertRecord
     * @exception EBaseException failed to add new certificate to
     * 		the repository
     */
    public void addRevokedCertRecord(CertRecord record)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();

        try {
            String name = "cn" + "=" +
                record.getSerialNumber().toString() + "," + getDN();

            s.add(name, record);
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * This transits a certificate status from VALID to EXPIRED
     * if a certificate becomes expired.
     */
    public void transitValidCertificates() throws EBaseException {

        Date now = CMS.getCurrentDate();
        ICertRecordList recList = getValidCertsByNotAfterDate(now, -1 * mTransitRecordPageSize);

        int size = recList.getSize();

        if (size <= 0) {
            CMS.debug("index may be empty");
            return;
        }
        int ltSize = recList.getSizeBeforeJumpTo();

        ltSize = Math.min(ltSize, mTransitMaxRecords);

        Vector cList = new Vector(ltSize);

        CMS.debug("transidValidCertificates: list size: " + size);
        CMS.debug("transitValidCertificates: ltSize " + ltSize);

        CertRecord curRec = null;

        int i;
        Object obj = null;

        for (i = 0; i < ltSize; i++) {
            obj = recList.getCertRecord(i);

            if (obj != null) {     
                curRec = (CertRecord) obj;

                Date notAfter = curRec.getNotAfter();

                //CMS.debug("notAfter " + notAfter.toString() + " now " + now.toString());
                if (notAfter.after(now)) {
                    CMS.debug("Record does not qualify,notAfter " + notAfter.toString() + " date " + now.toString());
                    continue;
                }

                CMS.debug("transitValid: curRec: " + i + " " + curRec.toString());

                if (mConsistencyCheck) {
                    cList.add(curRec);
                } else {
                    cList.add(curRec.getSerialNumber());
                }
            } else {
                CMS.debug("found null from getCertRecord");
            }
        }

        CertRecord cRec = null;
        BigInteger serial = null;

        transitCertList(cList, CertRecord.STATUS_EXPIRED);
    }

    /**
     * This transits a certificate status from REVOKED to REVOKED_EXPIRED
     * if an revoked certificate becomes expired.
     */
    public void transitRevokedExpiredCertificates() throws EBaseException {
        Date now = CMS.getCurrentDate();
        ICertRecordList recList = getRevokedCertsByNotAfterDate(now, -1 * mTransitRecordPageSize);
   
        int size = recList.getSize();

        if (size <= 0) {
            CMS.debug("index may be empty");
            return;
        }

        int ltSize = recList.getSizeBeforeJumpTo();
        Vector cList = new Vector(ltSize);

        ltSize = Math.min(ltSize, mTransitMaxRecords);

        CMS.debug("transitRevokedExpiredCertificates: list size: " + size);
        CMS.debug("transitRevokedExpiredCertificates: ltSize " + ltSize);

        CertRecord curRec = null;
        int i;
        Object obj = null;

        for (i = 0; i < ltSize; i++) {
            obj = recList.getCertRecord(i);
            if (obj != null) {
                curRec = (CertRecord) obj;
                CMS.debug("transitRevokedExpired: curRec: " + i + " " + curRec.toString());

                Date notAfter = curRec.getNotAfter();

                // CMS.debug("notAfter " + notAfter.toString() + " now " + now.toString());
                if (notAfter.after(now)) {
                    CMS.debug("Record does not qualify,notAfter " + notAfter.toString() + " date " + now.toString());
                    continue;
                }

                if (mConsistencyCheck) {
                    cList.add(curRec);
                } else {
                    cList.add(curRec.getSerialNumber());
                }
            }  else {
                CMS.debug("found null record in getCertRecord");
            }
        }

        transitCertList(cList, CertRecord.STATUS_REVOKED_EXPIRED);

    }

    /**
     * This transits a certificate status from INVALID to VALID
     * if a certificate becomes valid.
     */
    public void transitInvalidCertificates() throws EBaseException {

        Date now = CMS.getCurrentDate();

        ICertRecordList recList = getInvalidCertsByNotBeforeDate(now, -1 * mTransitRecordPageSize);

        int size = recList.getSize();

        if (size <= 0) {
            CMS.debug("index may be empty");
            return;
        }
        int ltSize = recList.getSizeBeforeJumpTo();

        ltSize = Math.min(ltSize, mTransitMaxRecords);

        Vector cList = new Vector(ltSize);

        CMS.debug("transidInValidCertificates: list size: " + size);
        CMS.debug("transitInValidCertificates: ltSize " + ltSize);

        CertRecord curRec = null;

        int i;

        Object obj = null;

        for (i = 0; i < ltSize; i++) {
            obj = recList.getCertRecord(i);

            if (obj != null) {
                curRec = (CertRecord) obj;

                Date notBefore = curRec.getNotBefore();

                //CMS.debug("notBefore " + notBefore.toString() + " now " + now.toString());
                if (notBefore.after(now)) {
                    CMS.debug("Record does not qualify,notBefore " + notBefore.toString() + " date " + now.toString());
                    continue;

                }
                CMS.debug("transitInValid: curRec: " + i + " " + curRec.toString());

                if (mConsistencyCheck) {
                    cList.add(curRec);
                } else {
                    cList.add(curRec.getSerialNumber());
                }

            } else {
                CMS.debug("found null from getCertRecord");
            }
        }

        transitCertList(cList, CertRecord.STATUS_VALID);

    }

    private void transitCertList(Vector cList, String newCertStatus) throws EBaseException {
        CertRecord cRec = null;
        BigInteger serial = null;

        int i;

        CMS.debug("transitCertList " + newCertStatus);

        for (i = 0; i < cList.size(); i++) {
            if (mConsistencyCheck) {
                cRec = (CertRecord) cList.elementAt(i);

                if (cRec == null)
                    continue;

                serial = cRec.getSerialNumber();
            } else {
                serial = (BigInteger) cList.elementAt(i);
            }

            updateStatus(serial, newCertStatus);

            if (newCertStatus.equals(CertRecord.STATUS_REVOKED_EXPIRED)) {
                
                // inform all CRLIssuingPoints about revoked and expired certificate

                Enumeration eIPs = mCRLIssuingPoints.elements();

                while (eIPs.hasMoreElements()) {
                    ICRLIssuingPoint ip = (ICRLIssuingPoint) eIPs.nextElement();

                    if (ip != null) {
                        ip.addExpiredCert(serial);
                    }
                }

            }

            CMS.debug("transitCertList number at: " + i + " = " + serial);
        }

        cList.removeAllElements();
    }

    /**
     * Reads the certificate identified by the given serial no.
     */
    public X509CertImpl getX509Certificate(BigInteger serialNo)
        throws EBaseException {
        X509CertImpl cert = null;
        ICertRecord cr = readCertificateRecord(serialNo);

        return (cr.getCertificate());
    }

    /**
     * Deletes certificate record.
     */
    public void deleteCertificateRecord(BigInteger serialNo)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();

        try {
            String name = "cn" + "=" +
                serialNo.toString() + "," + getDN();

            s.delete(name);
        } finally {
            if (s != null) 
                s.close();
        }
    }

    /**
     * Reads certificate from repository.
     */
    public ICertRecord readCertificateRecord(BigInteger serialNo)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        CertRecord rec = null;

        try {
            String name = "cn" + "=" +
                serialNo.toString() + "," + getDN();

            rec = (CertRecord) s.read(name);
        } finally {
            if (s != null) 
                s.close();
        }
        return rec;
    }

    public boolean checkCertificateRecord(BigInteger serialNo)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        CertRecord rec = null;
        boolean exists = true;

        try {
            String name = "cn" + "=" +
                serialNo.toString() + "," + getDN();
            String attrs[] = { "DN" };

            rec = (CertRecord) s.read(name, attrs);
            if (rec == null) exists = false;
        } catch (EDBRecordNotFoundException e) {
            exists = false;
        } catch (Exception e) {
            throw new EBaseException(e.getMessage());
        } finally {
            if (s != null) 
                s.close();
        }
        return exists;
    }

    private void setCertificateRepositoryMode(String mode) {
        IDBSSession s = null;

        CMS.debug("CertificateRepository: setCertificateRepositoryMode   setting mode: "+mode);
        try {
            s = mDBService.createSession();
            ModificationSet mods = new ModificationSet();
            String name = getDN();
            mods.add(IRepositoryRecord.ATTR_DESCRIPTION, Modification.MOD_REPLACE, mode);
            s.modify(name, mods);
        } catch (Exception e) {
            CMS.debug("CertificateRepository: setCertificateRepositoryMode   Exception: "+e.getMessage());
        }
        try {
            if (s != null) s.close();
        } catch (Exception e) {
            CMS.debug("CertificateRepository: setCertificateRepositoryMode   Exception: "+e.getMessage());
        }
    }

    public synchronized void modifyCertificateRecord(BigInteger serialNo,
        ModificationSet mods) throws EBaseException {
        IDBSSession s = mDBService.createSession();

        try {
            String name = "cn" + "=" +
                serialNo.toString() + "," + getDN();

            mods.add(CertRecord.ATTR_MODIFY_TIME, Modification.MOD_REPLACE,
                CMS.getCurrentDate());
            s.modify(name, mods);
        } finally {
            if (s != null) 
                s.close();
        }
    }

    /**
     * Checks if the specified certificate is in the repository.
     */
    public boolean containsCertificate(BigInteger serialNo)
        throws EBaseException {
        try {
            ICertRecord cr = readCertificateRecord(serialNo);

            if (cr != null)
                return true;
        } catch (EBaseException e) {
        }
        return false;
    }

    /**
     * Marks certificate as revoked.
     */
    public void markAsRevoked(BigInteger id, IRevocationInfo info)
        throws EBaseException {
        ModificationSet mods = new ModificationSet();

        mods.add(CertRecord.ATTR_REVO_INFO, Modification.MOD_ADD, info);
        SessionContext ctx = SessionContext.getContext();
        String uid = (String) ctx.get(SessionContext.USER_ID);

        if (uid == null) {
            mods.add(CertRecord.ATTR_REVOKED_BY, Modification.MOD_ADD,
                "system");
        } else {
            mods.add(CertRecord.ATTR_REVOKED_BY, Modification.MOD_ADD,
                uid);
        }
        mods.add(CertRecord.ATTR_REVOKED_ON, Modification.MOD_ADD,
            CMS.getCurrentDate());
        mods.add(CertRecord.ATTR_CERT_STATUS, Modification.MOD_REPLACE,
            CertRecord.STATUS_REVOKED);
        modifyCertificateRecord(id, mods);
    }

    /**
     * Unmarks revoked certificate.
     */
    public void unmarkRevoked(BigInteger id, IRevocationInfo info,
        Date revokedOn, String revokedBy)
        throws EBaseException {
        ModificationSet mods = new ModificationSet();

        mods.add(CertRecord.ATTR_REVO_INFO, Modification.MOD_DELETE, info);
        mods.add(CertRecord.ATTR_REVOKED_BY, Modification.MOD_DELETE, revokedBy);
        mods.add(CertRecord.ATTR_REVOKED_ON, Modification.MOD_DELETE, revokedOn);
        mods.add(CertRecord.ATTR_CERT_STATUS, Modification.MOD_REPLACE,
            CertRecord.STATUS_VALID);
        modifyCertificateRecord(id, mods);
    }

    /**
     * Updates the certificiate record status to the specified.
     */
    public void updateStatus(BigInteger id, String status)
        throws EBaseException {
        CMS.debug("updateStatus: " + id + " status " + status);
        ModificationSet mods = new ModificationSet();

        mods.add(CertRecord.ATTR_CERT_STATUS, Modification.MOD_REPLACE,
            status);
        modifyCertificateRecord(id, mods);
    }

    public Enumeration searchCertificates(String filter, int maxSize)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        CMS.debug("searchCertificates filter " + filter + " maxSize " + maxSize);
        try {
            e = s.search(getDN(), filter, maxSize);
        } finally {
            if (s != null) 
                s.close();
        }
        return e;
    }

    public Enumeration searchCertificates(String filter, int maxSize, int timeLimit)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        CMS.debug("searchCertificateswith time limit filter " + filter);
        try {
            e = s.search(getDN(), filter, maxSize, timeLimit);
        } finally {
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Returns a list of X509CertImp that satisfies the filter.
     * @deprecated replaced by <code>findCertificatesInList</code>
     */
    public Enumeration findCertRecs(String filter)
        throws EBaseException {
        CMS.debug("findCertRecs " + filter);
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;
        try {
            e = s.search(getDN(), filter);
        } finally {
            if (s != null) s.close();
        }
        return e;
    }

    public Enumeration findCertRecs(String filter, String[] attrs)
        throws EBaseException {

        CMS.debug( "findCertRecs " + filter
                 + "attrs " + Arrays.toString( attrs ) );
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;
        try {
            e = s.search(getDN(), filter, attrs);
        } finally {
            if (s != null) s.close();
        }
        return e;

    }

    public Enumeration findCertificates(String filter)
        throws EBaseException {
        Enumeration e = findCertRecords(filter);
        Vector v = new Vector();

        while (e.hasMoreElements()) {
            CertRecord rec = (CertRecord) e.nextElement();

            v.addElement(rec.getCertificate());
        }
        return v.elements();
    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     * If you are going to process everything in the list,
     * use this.
     */
    public Enumeration findCertRecords(String filter)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            //e = s.search(getDN(), filter);
            ICertRecordList list = null;

            list = findCertRecordsInList(filter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        } finally {
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Finds certificate records. Here is a list of filter
     * attribute can be used:
     * <pre>
     *   certRecordId
     *   certMetaInfo
     *   certStatus
     *   certCreateTime
     *   certModifyTime
     *   x509Cert.notBefore
     *   x509Cert.notAfter
     *   x509Cert.subject
     * </pre>
     * The filter should follow RFC1558 LDAP filter syntax.
     * For example,
     * <pre>
     *   (&(certRecordId=5)(x509Cert.notBefore=934398398))
     * </pre>
     */
    public ICertRecordList findCertRecordsInList(String filter, 
        String attrs[], int pageSize) throws EBaseException {
        return findCertRecordsInList(filter, attrs, CertRecord.ATTR_ID, 
                pageSize);
    }

    public ICertRecordList findCertRecordsInList(String filter, 
        String attrs[], String sortKey, int pageSize) 
        throws EBaseException {
        IDBSSession s = mDBService.createSession();

        CMS.debug("In findCertRecordsInList");
        CertRecordList list = null;

        try {
            DBVirtualList vlist = (DBVirtualList) s.createVirtualList(getDN(), filter, attrs,
                    sortKey, pageSize);

            list = new CertRecordList(vlist);
        } finally {
            if (s != null) 
                s.close();
        }
        return list;
    }

    public ICertRecordList findCertRecordsInList(String filter, 
		 String attrs[], String jumpTo, String sortKey, int pageSize)
        throws EBaseException {
	return findCertRecordsInList(filter, attrs, jumpTo, false, sortKey, pageSize);

    }

    public ICertRecordList findCertRecordsInList(String filter, 
		 String attrs[], String jumpTo, boolean hardJumpTo,
						 String sortKey, int pageSize)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        CertRecordList list = null;

        CMS.debug("In findCertRecordsInList with Jumpto " + jumpTo);
        try {
            String jumpToVal = null;

	    if (hardJumpTo) {
        CMS.debug("In findCertRecordsInList with hardJumpto ");
		jumpToVal = "99";
	    } else {
            int len = jumpTo.length();

            if (len > 9) {
                jumpToVal = Integer.toString(len) + jumpTo;
            } else {
                jumpToVal = "0" + Integer.toString(len) + jumpTo;
            }
	    }

            DBVirtualList vlist = (DBVirtualList) s.createVirtualList(getDN(), filter, 
                    attrs, jumpToVal, sortKey, pageSize);

            list = new CertRecordList(vlist);
        } finally {
            if (s != null) 
                s.close();
        }
        return list;
    }

    public ICertRecordList findCertRecordsInListRawJumpto(String filter,
        String attrs[], String jumpTo, String sortKey, int pageSize)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        CertRecordList list = null;

        CMS.debug("In findCertRecordsInListRawJumpto with Jumpto " + jumpTo);

        try {

            DBVirtualList vlist = (DBVirtualList) s.createVirtualList(getDN(), filter,
                    attrs, jumpTo, sortKey, pageSize);

            list = new CertRecordList(vlist);
        } finally {
            if (s != null)
                s.close();
        }
        return list;
    }

    /**
     * Marks certificate as renewable.
     */
    public void markCertificateAsRenewable(ICertRecord record)
        throws EBaseException {
        changeRenewalAttribute(((CertRecord) record).getSerialNumber().toString(),
            CertRecord.AUTO_RENEWAL_ENABLED);
    }

    /**
     * Marks certificate as renewable.
     */
    public void markCertificateAsNotRenewable(ICertRecord record)
        throws EBaseException {
        changeRenewalAttribute(((CertRecord) record).getSerialNumber().toString(),
            CertRecord.AUTO_RENEWAL_DISABLED);
    }

    public void markCertificateAsRenewed(String serialNo)
        throws EBaseException {
        changeRenewalAttribute(serialNo, CertRecord.AUTO_RENEWAL_DONE);
    }

    public void markCertificateAsRenewalNotified(String serialNo)
        throws EBaseException {
        changeRenewalAttribute(serialNo, CertRecord.AUTO_RENEWAL_NOTIFIED);
    }

    private void changeRenewalAttribute(String serialno, String value)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();

        try {
            String name = "cn" + "=" + serialno +
                "," + getDN();
            ModificationSet mods = new ModificationSet();

            mods.add(CertRecord.ATTR_AUTO_RENEW, Modification.MOD_REPLACE,
                value);
            s.modify(name, mods);
        } finally {
            if (s != null) 
                s.close();
        }
    }

    /**
     * temp solution...
     */
    public class RenewableCertificateCollection {
        Vector mToRenew = null;
        Vector mToNotify = null;
        public RenewableCertificateCollection() {
        }

        public Vector getRenewable() {
            return mToRenew;
        }

        public Vector getNotifiable() {
            return mToNotify;
        }

        public void addCertificate(String renewalFlag, Object o) {
            if (renewalFlag.equals(CertRecord.AUTO_RENEWAL_ENABLED)) {
                if (mToRenew == null)
                    mToRenew = new Vector();
                mToRenew.addElement(o);
            }
            if (renewalFlag.equals(CertRecord.AUTO_RENEWAL_DISABLED)) {
                if (mToNotify == null)
                    mToNotify = new Vector();
                mToNotify.addElement(o);
            }
        }
    }

    public Hashtable getRenewableCertificates(String renewalTime)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();

        Hashtable tab = null;

        try {
            String filter = "(&(" + CertRecord.ATTR_CERT_STATUS + "=" +
                CertRecord.STATUS_VALID + ")("
                + CertRecord.ATTR_X509CERT +
                "." + CertificateValidity.NOT_AFTER + "<=" + renewalTime +
                ")(!(" + CertRecord.ATTR_AUTO_RENEW + "=" +
                CertRecord.AUTO_RENEWAL_DONE +
                "))(!(" + CertRecord.ATTR_AUTO_RENEW + "=" +
                CertRecord.AUTO_RENEWAL_NOTIFIED + ")))";
            //Enumeration e = s.search(getDN(), filter);
            ICertRecordList list = null;

            list = findCertRecordsInList(filter, null, "serialno", 10);
            int size = list.getSize();
            Enumeration e = list.getCertRecords(0, size - 1);

            tab = new Hashtable();
            while (e.hasMoreElements()) {
                CertRecord rec = (CertRecord) e.nextElement();
                X509CertImpl cert = rec.getCertificate();
                String subjectDN = cert.getSubjectDN().toString();
                String renewalFlag = rec.getAutoRenew();

                // See if the subjectDN is in the table
                Object val = null;

                if ((val = tab.get(subjectDN)) == null) {
                    RenewableCertificateCollection collection =
                        new RenewableCertificateCollection();

                    collection.addCertificate(renewalFlag, cert);
                    tab.put(subjectDN, collection);
                } else {
                    ((RenewableCertificateCollection) val).addCertificate(renewalFlag, cert);
                }
            }
        } finally {
            if (s != null) 
                s.close();
        }
        return tab;
    }

    /**
     * Gets all valid and unexpired certificates pertaining
     * to a subject DN.
     *
     * @param subjectDN	The distinguished name of the subject.
     * @param validityType	The type of certificates to get.
     * @return An array of certificates.
     */

    public X509CertImpl[] getX509Certificates(String subjectDN,
        int validityType) throws EBaseException {
        IDBSSession s = mDBService.createSession();

        X509CertImpl certs[] = null;

        try {
            // XXX - not checking validityType...
            String filter = "(&(" + CertRecord.ATTR_X509CERT +
                "." + X509CertInfo.SUBJECT + "=" + subjectDN;

            if (validityType == ALL_VALID_CERTS) {
                filter += ")(" +
                        CertRecord.ATTR_CERT_STATUS + "=" +
                        CertRecord.STATUS_VALID;
            }
            if (validityType == ALL_UNREVOKED_CERTS) {
                filter += ")(|(" +
                        CertRecord.ATTR_CERT_STATUS + "=" +
                        CertRecord.STATUS_VALID + ")(" +
                        CertRecord.ATTR_CERT_STATUS + "=" +
                        CertRecord.STATUS_EXPIRED + ")";
            }
            filter += "))";

            //Enumeration e = s.search(getDN(), filter);
            ICertRecordList list = null;

            list = findCertRecordsInList(filter, null, "serialno", 10);
            int size = list.getSize();
            Enumeration e = list.getCertRecords(0, size - 1);

            Vector v = new Vector();

            while (e.hasMoreElements()) {
                CertRecord rec = (CertRecord) e.nextElement();

                v.addElement(rec.getCertificate());
            }
            if (v.size() == 0)
                return null;
            certs = new X509CertImpl[v.size()];
            v.copyInto(certs);
        } finally {
            if (s != null) 
                s.close();
        }
        return certs;
    }

    public X509CertImpl[] getX509Certificates(String filter)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();

        X509CertImpl certs[] = null;

        try {
            Enumeration e = null;

            if (filter != null && filter.length() > 0) {
                //e = s.search(getDN(), filter);
                ICertRecordList list = null;

                list = findCertRecordsInList(filter, null, "serialno", 10);
                int size = list.getSize();

                e = list.getCertRecords(0, size - 1);
            }

            Vector v = new Vector();

            while (e != null && e.hasMoreElements()) {
                CertRecord rec = (CertRecord) e.nextElement();

                v.addElement(rec.getCertificate());
            }
            if (v.size() > 0) {
                certs = new X509CertImpl[v.size()];
                v.copyInto(certs);
            }
        } finally {
            if (s != null) 
                s.close();
        }
        return certs;
    }

    /**
     * Retrives all valid certificates excluding ones already revoked.
     * @param from	The starting point of the serial number range.
     * @param to	The ending point of the serial number range.
     */
    public Enumeration getValidCertificates(String from, String to)
		throws EBaseException {
			IDBSSession s = mDBService.createSession();
			Vector v = new Vector();

			try {

				// 'from' determines 'jumpto' value
				// 'to' determines where to stop looking

				String ldapfilter = "(certstatus=VALID)";

                String fromVal = "0";
                try {
                    if (from != null) {
                      new BigInteger(from);
                      fromVal = from;
                    }
                } catch (Exception e1) {
                   // from is not integer
                }

				ICertRecordList list = 
					findCertRecordsInList(ldapfilter, null, fromVal, "serialno", 40);

				BigInteger toInt = null;
                if (to != null && !to.trim().equals("")) {
                  toInt = new BigInteger(to);
                }

				for (int i=0;; i++) {
					CertRecord rec = (CertRecord) list.getCertRecord(i);
					CMS.debug("processing record: "+i);
					if (rec == null) {
                         break; // no element returned
                    } else {

					     CMS.debug("processing record: "+i+" "+rec.getSerialNumber());
						// Check if we are past the 'to' marker
                        if (toInt != null) {
						  if (rec.getSerialNumber().compareTo(toInt) > 0) {
							break;
						  }
                        }
						v.addElement(rec);
					}
				}

			} finally {
				if (s != null) 
					s.close();
			}
			CMS.debug("returning "+v.size()+" elements");
			return v.elements();
		}

    /**
     * Retrives all valid certificates excluding ones already revoked.
     */
    public Enumeration getAllValidCertificates()
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            Date now = CMS.getCurrentDate();
            String ldapfilter = "(&(!(" + CertRecord.ATTR_REVO_INFO + "=*))(" +
                CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_BEFORE + "<=" +
                DateMapper.dateToDB(now) + ")(" +
                CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_AFTER + ">=" +
                DateMapper.dateToDB(now) + "))";
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
								 
        } finally {
            // XXX - transaction is not done at this moment
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrives all valid not published certificates 
     * excluding ones already revoked.
     * @param from	The starting point of the serial number range.
     * @param to	The ending point of the serial number range.
     */
    public Enumeration getValidNotPublishedCertificates(String from, String to)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            Date now = CMS.getCurrentDate();
            String ldapfilter = "(&(";

            if (from != null && from.length() > 0)
                ldapfilter += CertRecord.ATTR_ID + ">=" + from + ")(";
            if (to != null && to.length() > 0)
                ldapfilter += CertRecord.ATTR_ID + "<=" + to + ")(";
            ldapfilter += "!(" + CertRecord.ATTR_REVO_INFO + "=*))(" +
                    CertRecord.ATTR_X509CERT + "." +
                    CertificateValidity.NOT_BEFORE + "<=" +
                    DateMapper.dateToDB(now) + ")(" +
                    CertRecord.ATTR_X509CERT + "." +
                    CertificateValidity.NOT_AFTER + ">=" +
                    DateMapper.dateToDB(now) + ")(!(" +
                    "certMetainfo=" +
                    CertRecord.META_LDAPPUBLISH +
                    ":true)))";
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
								 
        } finally {
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrives all valid not published certificates 
     * excluding ones already revoked.
     */
    public Enumeration getAllValidNotPublishedCertificates()
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            Date now = CMS.getCurrentDate();
            String ldapfilter = "(&(!(" + CertRecord.ATTR_REVO_INFO + "=*))(" +
                CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_BEFORE + "<=" +
                DateMapper.dateToDB(now) + ")(" +
                CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_AFTER + ">=" +
                DateMapper.dateToDB(now) + ")(!(" +
                "certMetainfo=" +
                CertRecord.META_LDAPPUBLISH +
                ":true)))";
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
								 
        } finally {
            // XXX - transaction is not done at this moment
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrives all expired certificates.
     * @param from	The starting point of the serial number range.
     * @param to	The ending point of the serial number range.
     */
    public Enumeration getExpiredCertificates(String from, String to)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            Date now = CMS.getCurrentDate();
            String ldapfilter = "(&(";

            if (from != null && from.length() > 0)
                ldapfilter += CertRecord.ATTR_ID + ">=" + from + ")(";
            if (to != null && to.length() > 0)
                ldapfilter += CertRecord.ATTR_ID + "<=" + to + ")(";
            ldapfilter += "!(" + CertRecord.ATTR_X509CERT + "." +
                    CertificateValidity.NOT_AFTER + ">=" +
                    DateMapper.dateToDB(now) + ")))";
            //e = s.search(getDN(), ldapfilter);
								 
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        } finally { 
            // XXX - transaction is not done at this moment
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrives all expired certificates.
     */
    public Enumeration getAllExpiredCertificates()
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            Date now = CMS.getCurrentDate();
            String ldapfilter = "(!(" + CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_AFTER + ">=" +
                DateMapper.dateToDB(now) + "))";
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
								 
        } finally { 
            // XXX - transaction is not done at this moment
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrives all expired published certificates.
     * @param from	The starting point of the serial number range.
     * @param to	The ending point of the serial number range.
     */
    public Enumeration getExpiredPublishedCertificates(String from, String to)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            Date now = CMS.getCurrentDate();
            String ldapfilter = "(&(";

            if (from != null && from.length() > 0)
                ldapfilter += CertRecord.ATTR_ID + ">=" + from + ")(";
            if (to != null && to.length() > 0)
                ldapfilter += CertRecord.ATTR_ID + "<=" + to + ")(";
            ldapfilter += "!(" + CertRecord.ATTR_X509CERT + "." +
                    CertificateValidity.NOT_AFTER + ">=" +
                    //DateMapper.dateToDB(now) + ")))";
                    DateMapper.dateToDB(now) + "))(" +
                    "certMetainfo=" +
                    CertRecord.META_LDAPPUBLISH +
                    ":true))";
            //e = s.search(getDN(), ldapfilter);
								 
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        } finally { 
            // XXX - transaction is not done at this moment
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrives all expired publishedcertificates.
     */
    public Enumeration getAllExpiredPublishedCertificates()
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            Date now = CMS.getCurrentDate();
            String ldapfilter = "(&";

            ldapfilter += "(!(" + CertRecord.ATTR_X509CERT + "." +
                    CertificateValidity.NOT_AFTER + ">=" +
                    DateMapper.dateToDB(now) + "))";
            ldapfilter += "(certMetainfo=" +
                    CertRecord.META_LDAPPUBLISH +
                    ":true))";
		
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
								 
        } finally { 
            // XXX - transaction is not done at this moment
            if (s != null) 
                s.close();
        }
        return e;
    }

    public ICertRecordList getInvalidCertsByNotBeforeDate(Date date, int pageSize)
        throws EBaseException {

        String now = null;

        Date rightNow = CMS.getCurrentDate();

        ICertRecordList list = null;
        IDBSSession s = mDBService.createSession();

        try {
            String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_INVALID + ")";

            String[] attrs = null;

            if (mConsistencyCheck == false) {
                attrs = new String[] { "objectclass", CertRecord.ATTR_ID, CertRecord.ATTR_X509CERT};
            }

            CMS.debug("getInvalidCertificatesByNotBeforeDate filter " + ldapfilter);
            //e = s.search(getDN(), ldapfilter);
            CMS.debug("getInvalidCertificatesByNotBeforeDate: about to call findCertRecordsInList");

            list = findCertRecordsInListRawJumpto(ldapfilter, attrs,
                        DateMapper.dateToDB(date), "notBefore", pageSize);

            //e = list.getCertRecords(0, size - 1);

        } finally {
            // XXX - transaction is not done at this moment


            CMS.debug("In getInvalidCertsByNotBeforeDate finally.");

            if (s != null)
                s.close();
        }
        return list;

    }

    public ICertRecordList getValidCertsByNotAfterDate(Date date, int pageSize)
        throws EBaseException {

        String now = null;

        ICertRecordList list = null;
        IDBSSession s = mDBService.createSession();

        try {
            String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_VALID + ")";

            String[] attrs = null;

            if (mConsistencyCheck == false) {
                attrs = new String[] { "objectclass", CertRecord.ATTR_ID, CertRecord.ATTR_X509CERT};
            }

            CMS.debug("getValidCertsByNotAfterDate filter " + ldapfilter);
            //e = s.search(getDN(), ldapfilter);
            list = findCertRecordsInListRawJumpto(ldapfilter, attrs, DateMapper.dateToDB(date), "notAfter", pageSize);

        } finally {
            // XXX - transaction is not done at this moment

            if (s != null)
                s.close();
        }
        return list;
    }

    public ICertRecordList getRevokedCertsByNotAfterDate(Date date, int pageSize)
        throws EBaseException {

        ICertRecordList list = null;
        IDBSSession s = mDBService.createSession();

        try {
            String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")";

            String[] attrs = null;

            if (mConsistencyCheck == false) {
                attrs = new String[] { "objectclass", CertRecord.ATTR_REVOKED_ON, CertRecord.ATTR_ID,
                            CertRecord.ATTR_REVO_INFO, CertificateValidity.NOT_AFTER, CertRecord.ATTR_X509CERT};
            }

            CMS.debug("getRevokedCertificatesByNotAfterDate filter " + ldapfilter);
            //e = s.search(getDN(), ldapfilter);
            CMS.debug("getRevokedCertificatesByNotAfterDate: about to call findCertRecordsInList");

            list = findCertRecordsInListRawJumpto(ldapfilter, attrs,
                        DateMapper.dateToDB(date), "notafter", pageSize);

        } finally {
            // XXX - transaction is not done at this moment


            if (s != null)
                s.close();
        }
        return list;

    }
    
    /**
     * Retrieves all revoked certificates in the serial number range. 
     * @param from	The starting point of the serial number range.
     * @param to	The ending point of the serial number range.
     */
    public Enumeration getRevokedCertificates(String from, String to)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            String ldapfilter = "(&(" + CertRecord.ATTR_REVO_INFO + "=*)";

            if (from != null && from.length() > 0)
                ldapfilter += "(" + CertRecord.ATTR_ID + ">=" + from + ")";
            if (to != null && to.length() > 0)
                ldapfilter += "(" + CertRecord.ATTR_ID + "<=" + to + ")";
            ldapfilter += ")";
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        } finally {
            // XXX - transaction is not done at this moment
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrives all revoked certificates including ones already expired or 
     * not yet valid.
     */
    public Enumeration getAllRevokedCertificates()
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;
        String ldapfilter = "(|(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED_EXPIRED + "))"; // index is setup for this filter

        try {
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        } finally {
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrieves all revoked publishedcertificates in the serial number range. 
     * @param from	The starting point of the serial number range.
     * @param to	The ending point of the serial number range.
     */
    public Enumeration getRevokedPublishedCertificates(String from, String to)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {
            String ldapfilter = "(&(" + CertRecord.ATTR_REVO_INFO + "=*)";

            if (from != null && from.length() > 0)
                ldapfilter += "(" + CertRecord.ATTR_ID + ">=" + from + ")";
            if (to != null && to.length() > 0)
                ldapfilter += "(" + CertRecord.ATTR_ID + "<=" + to + ")";
                //ldapfilter += ")";
            ldapfilter += "(certMetainfo=" +
                    CertRecord.META_LDAPPUBLISH +
                    ":true))";
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        } finally {
            // XXX - transaction is not done at this moment
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrives all revoked published certificates including ones 
     * already expired or not yet valid.
     */
    public Enumeration getAllRevokedPublishedCertificates()
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;
        String ldapfilter = "(&(|(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED_EXPIRED + "))"; // index is setup for this filter

        ldapfilter += "(certMetainfo=" +
                CertRecord.META_LDAPPUBLISH +
                ":true))";
        try {
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        } finally {
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrieves all revoked certificates that have not expired. 
     */
    public Enumeration getRevokedCertificates(Date asOfDate)
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;

        try {

            /*e = s.search(getDN(), "(&(" +
             CertRecord.ATTR_REVO_INFO + "=*)(" + CertRecord.ATTR_X509CERT +
             "." +  CertificateValidity.NOT_AFTER + " >= " +
             DateMapper.dateToDB(asOfDate) + "))");*/
            String ldapfilter = "(&(" +
                CertRecord.ATTR_REVO_INFO + "=*)(" + CertRecord.ATTR_X509CERT +
                "." + CertificateValidity.NOT_AFTER + " >= " +
                DateMapper.dateToDB(asOfDate) + "))";
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        } finally {
            // XXX - transaction is not done at this moment
            if (s != null) 
                s.close();
        }
        return e;
    }

    /**
     * Retrives all revoked certificates excluing ones already expired.
     */
    public Enumeration getAllRevokedNonExpiredCertificates()
        throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration e = null;
        String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")"; // index is setup for this filter

        try {
            //e = s.search(getDN(), ldapfilter);
            ICertRecordList list = null;

            list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        } finally {
            if (s != null) 
                s.close();
        }
        return e;
    }

    private LDAPSearchResults startSearchForModifiedCertificateRecords()
        throws EBaseException {
        CMS.debug("startSearchForModifiedCertificateRecords");
        LDAPSearchResults r = null;
        IDBSSession s = mDBService.createSession();

        String filter = "(" + CertRecord.ATTR_CERT_STATUS + "=*)";
        try {
            r = s.persistentSearch(getDN(), filter, null);
            CMS.debug("startSearchForModifiedCertificateRecords  persistentSearch started");
        } catch (Exception e) {
            CMS.debug("startSearchForModifiedCertificateRecords  persistentSearch Exception="+e);
            r = null;
            if (s != null) 
                s.close();
        }
        return r;
    }

    public void getModifications(LDAPEntry entry) {
        if (entry != null) {
            CMS.debug("getModifications  entry DN="+entry.getDN());

            LDAPAttributeSet entryAttrs = entry.getAttributeSet();
            ICertRecord certRec = null;
            try {
                certRec = (ICertRecord)mDBService.getRegistry().createObject(entryAttrs);
            } catch (Exception e) {
            }
            if (certRec != null) {
                String status = certRec.getStatus();
                CMS.debug("getModifications  serialNumber="+certRec.getSerialNumber()+
                          "  status="+status);
                if (status != null && (status.equals(ICertRecord.STATUS_VALID) ||
                    status.equals(ICertRecord.STATUS_REVOKED))) {

                    Enumeration eIPs = mCRLIssuingPoints.elements();

                    while (eIPs.hasMoreElements()) {
                        ICRLIssuingPoint ip = (ICRLIssuingPoint) eIPs.nextElement();

                        if (ip != null) {
                            if (status.equals(ICertRecord.STATUS_REVOKED)) {
                                IRevocationInfo rInfo = certRec.getRevocationInfo();
                                if (rInfo != null) {
                                    ip.addRevokedCert(certRec.getSerialNumber(),
                                        new RevokedCertImpl(certRec.getSerialNumber(),
                                                            rInfo.getRevocationDate(),
                                                            rInfo.getCRLEntryExtensions()));
                                }
                            } else {
                                ip.addUnrevokedCert(certRec.getSerialNumber());
                            }
                        }
                    }

                }
            }
        } else {
            CMS.debug("getModifications  entry == null");
        }
    }


    /**
     * Checks if the presented certificate belongs to the repository
     * and is revoked.
     *
     * @param cert	certificate to verify.
     * @return RevocationInfo if the presented certificate is revoked otherwise null.
     */
    public RevocationInfo isCertificateRevoked(X509CertImpl cert)
        throws EBaseException {
        RevocationInfo info = null;

        // 615932
        if (cert == null)
            return null;

        ICertRecord rec = readCertificateRecord(cert.getSerialNumber());

        if (rec != null) {
            if (rec.getStatus().equals(ICertRecord.STATUS_REVOKED)) {
                X500Name name = (X500Name) cert.getSubjectDN();
                X500Name repCertName = (X500Name) rec.getCertificate().getSubjectDN();

                if (name.equals(repCertName)) {
                    byte[] certEncoded = null;
                    byte[] repCertEncoded = null;

                    try {
                        certEncoded = cert.getEncoded();
                        repCertEncoded = rec.getCertificate().getEncoded();
                    } catch (Exception e) {
                    }

                    if (certEncoded != null &&
                        repCertEncoded != null &&
                        certEncoded.length == repCertEncoded.length) {
                        int i;

                        for (i = 0; i < certEncoded.length; i++) {
                            if (certEncoded[i] != repCertEncoded[i])
                                break;
                        }
                        if (i >= certEncoded.length) {
                            info = (RevocationInfo) ((CertRecord) rec).getRevocationInfo();
                        }
                    }
                }
            }
        }

        return info;
    }

    public void shutdown() {
        //if (mCertStatusUpdateThread != null) 
        //        mCertStatusUpdateThread.destroy();

        //if (mRetrieveModificationsThread != null) 
        //        mRetrieveModificationsThread.destroy();
    }
}


class CertStatusUpdateThread extends Thread {
    CertificateRepository _cr = null;
    IRepository _rr = null;
    int _interval;

    CertStatusUpdateThread(CertificateRepository cr, IRepository rr, String name) {
        super(name);
        CMS.debug("new CertStatusUpdateThread");
        //setName(name);

        _cr = cr;
        _rr = rr;
    }

    public void setInterval(int interval) {
        _interval = interval;
    }

    public void run() {
        CMS.debug("Inside run method of CertStatusUpdateThread");

        while (true) {
            try {
                // block the update while another thread
                // (such as the CRL Update) is running
                CMS.debug("About to start updateCertStatus");
                synchronized (_cr.mCertStatusUpdateThread) {
                    CMS.debug("Starting updateCertStatus (entered lock)");
                    _cr.updateCertStatus();
                    CMS.debug("updateCertStatus done");

                    CMS.debug("Starting cert checkRanges");
                    _cr.checkRanges();
                    CMS.debug("cert checkRanges done");

                    CMS.debug("Starting request checkRanges");
                    _rr.checkRanges();
                    CMS.debug("request checkRanges done");
                }

            } catch (Exception e) {
                CMS.debug("updateCertStatus done: " + e.toString());
            }
            try {
                sleep(_interval * 1000);
            } catch (InterruptedException e) {
            }
        }
    }
}


class RetrieveModificationsThread extends Thread {
    CertificateRepository _cr = null;
    LDAPSearchResults _results = null;

    RetrieveModificationsThread(CertificateRepository cr, String name) {
        super(name);
        CMS.debug("new RetrieveModificationsThread");
        //setName(name);

        _cr = cr;
    }

    public void setResults(LDAPSearchResults results) {
        _results = results;
    }

    public void run() {
        CMS.debug("Inside run method of RetrieveModificationsThread");

        if (_results != null) {
            try {
                while (_results.hasMoreElements()) {
                    LDAPEntry entry = _results.next();
                    _cr.getModifications(entry);
                }
            } catch (LDAPException e) {
                CMS.debug("LDAPException: "+e.toString());
            }
        } else {
            CMS.debug("_results are null");
        }
        CMS.debug("Done with run method of RetrieveModificationsThread");
    }
}

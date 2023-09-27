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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.DBVirtualList;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.RenewableCertificateCollection;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;

import netscape.ldap.LDAPSearchResults;

/**
 * A classrepresents a certificate repository.
 * It stores all the issued certificate.
 *
 * @author thomask
 * @author kanda
 * @version $Revision$, $Date$
 */
public class CertificateRepository extends Repository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertificateRepository.class);

    public final static int ALL_CERTS = 0;
    public final static int ALL_VALID_CERTS = 1;
    public final static int ALL_UNREVOKED_CERTS = 2;

    public final static String PROP_INCREMENT = "certdbInc";
    public final static String PROP_TRANS_MAXRECORDS = "transitMaxRecords";
    public final static String PROP_TRANS_PAGESIZE = "transitRecordPageSize";

    public final String CERT_X509ATTRIBUTE = "x509signedcert";
    private static final String PROP_ENABLE_RANDOM_SERIAL_NUMBERS = "enableRandomSerialNumbers";
    private static final String PROP_RANDOM_SERIAL_NUMBER_COUNTER = "randomSerialNumberCounter";
    private static final String PROP_FORCE_MODE_CHANGE = "forceModeChange";
    private static final String PROP_RANDOM_MODE = "random";
    private static final String PROP_SEQUENTIAL_MODE = "sequential";
    private static final String PROP_COLLISION_RECOVERY_STEPS = "collisionRecoverySteps";
    private static final String PROP_COLLISION_RECOVERY_REGENERATIONS = "collisionRecoveryRegenerations";
    private static final String PROP_MINIMUM_RANDOM_BITS = "minimumRandomBits";
    private static final BigInteger BI_MINUS_ONE = BigInteger.ONE.negate();

    public static final String PROP_CERT_ID_GENERATOR = "cert.id.generator";
    public static final String DEFAULT_CERT_ID_GENERATOR = "legacy";

    public static final String PROP_CERT_ID_LENGTH = "cert.id.length";

    private boolean mConsistencyCheck = false;

    private boolean mEnableRandomSerialNumbers;
    private int mBitLength = 0;
    private BigInteger mRangeSize = null;
    private int mMinRandomBitLength = 4;
    private int mMaxCollisionRecoverySteps = 10;
    private int mMaxCollisionRecoveryRegenerations = 3;
    private DatabaseConfig mDBConfig = null;
    private boolean mForceModeChange = false;

    /**
     * Constructs a certificate repository.
     */
    public CertificateRepository(
            SecureRandom secureRandom,
            DBSubsystem dbSubsystem) {

        super(dbSubsystem, 16);

        this.secureRandom = secureRandom;
    }

    @Override
    public void init() throws Exception {

        logger.debug("CertificateRepository: Initializing certificate repository");

        mDBConfig = dbSubsystem.getDBConfigStore();

        mBaseDN = mDBConfig.getSerialDN() + "," + dbSubsystem.getBaseDN();
        logger.debug("CertificateRepository: - base DN: " + mBaseDN);

        String value = mDBConfig.getString(PROP_CERT_ID_GENERATOR, DEFAULT_CERT_ID_GENERATOR);
        logger.debug("CertificateRepository: - cert ID generator: " + value);
        setIDGenerator(value);

        if (idGenerator == IDGenerator.RANDOM) {

            idLength = mDBConfig.getInteger(PROP_CERT_ID_LENGTH);
            logger.debug("CertificateRepository: - cert ID length: " + idLength);

        } else {
            initLegacyGenerator();
        }
    }

    public void initLegacyGenerator() throws Exception {

        rangeDN = mDBConfig.getSerialRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.debug("CertificateRepository: - range DN: " + rangeDN);

        minSerialName = DatabaseConfig.MIN_SERIAL_NUMBER;
        String minSerial = mDBConfig.getBeginSerialNumber();
        if (minSerial != null) {
            mMinSerialNo = new BigInteger(minSerial, mRadix);
        }
        logger.debug("CertificateRepository: - min serial: " + mMinSerialNo);

        maxSerialName = DatabaseConfig.MAX_SERIAL_NUMBER;
        String maxSerial = mDBConfig.getEndSerialNumber();
        if (maxSerial != null) {
            mMaxSerialNo = new BigInteger(maxSerial, mRadix);
        }
        logger.debug("CertificateRepository: - max serial: " + mMaxSerialNo);

        nextMinSerialName = DatabaseConfig.NEXT_MIN_SERIAL_NUMBER;
        String nextMinSerial = mDBConfig.getNextBeginSerialNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = new BigInteger(nextMinSerial, mRadix);
        }
        logger.debug("CertificateRepository: - next min serial: " + mNextMinSerialNo);

        nextMaxSerialName = DatabaseConfig.NEXT_MAX_SERIAL_NUMBER;
        String nextMaxSerial = mDBConfig.getNextEndSerialNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = new BigInteger(nextMaxSerial, mRadix);
        }
        logger.debug("CertificateRepository: - next max serial: " + mNextMaxSerialNo);

        String lowWaterMark = mDBConfig.getSerialLowWaterMark();
        if (lowWaterMark != null) {
            mLowWaterMarkNo = new BigInteger(lowWaterMark, mRadix);
        }

        String incrementNo = mDBConfig.getSerialIncrement();
        if (incrementNo != null) {
            mIncrementNo = new BigInteger(incrementNo, mRadix);
        }
    }

    /**
     * Retrieves serial number management mode.
     *
     * @return serial number management mode,
     * "true" indicates random serial number management,
     * "false" indicates sequential serial number management.
     */
    public boolean getEnableRandomSerialNumbers() {
        return mEnableRandomSerialNumbers;
    }

    /**
     * Sets serial number management mode for certificates..
     *
     * @param random "true" sets random serial number management, "false" sequential
     * @param updateMode "true" updates "description" attribute in certificate repository
     * @param forceModeChange "true" forces certificate repository mode change
     */
    public void setEnableRandomSerialNumbers(boolean random, boolean updateMode, boolean forceModeChange) {
        logger.debug("CertificateRepository:  setEnableRandomSerialNumbers   random="+random+"  updateMode="+updateMode);

        EngineConfig cs = engine.getConfig();

        if (mEnableRandomSerialNumbers ^ random || forceModeChange) {
            mEnableRandomSerialNumbers = random;
            logger.debug("CertificateRepository:  setEnableRandomSerialNumbers   switching to " +
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
                    logger.debug("CertificateRepository:  setEnableRandomSerialNumbers  mCounter="+
                               mCounter+"="+lastSerialNumber+"-"+mMinSerialNo+"+1");
                    long t = System.currentTimeMillis();
                    mDBConfig.putString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, mCounter.toString()+","+t);
                } else {
                    mCounter = BI_MINUS_ONE;
                    mDBConfig.putString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, mCounter.toString());
                }
            }

            try {
                cs.commit(false);
            } catch (Exception e) {
            }
        }
    }

    private BigInteger getRandomNumber() throws EBaseException {

        initCache();

        if (mRangeSize == null) {
            mRangeSize = (mMaxSerialNo.subtract(mMinSerialNo)).add(BigInteger.ONE);
            logger.debug("CertificateRepository: getRandomNumber  mRangeSize="+mRangeSize);
            mBitLength = mRangeSize.bitLength();
            logger.debug("CertificateRepository: getRandomNumber  mBitLength="+mBitLength+
                      " >mMinRandomBitLength="+mMinRandomBitLength);
        }
        if (mBitLength < mMinRandomBitLength) {
            logger.debug("CertificateRepository: getRandomNumber  mBitLength="+mBitLength+
                      " <mMinRandomBitLength="+mMinRandomBitLength);
            logger.debug("CertificateRepository: getRandomNumber:  Range size is too small to support random certificate serial numbers.");
            throw new EBaseException ("Range size is too small to support random certificate serial numbers.");
        }

        BigInteger randomNumber = new BigInteger(mBitLength, secureRandom);
        randomNumber = (randomNumber.multiply(mRangeSize)).shiftRight(mBitLength);
        logger.debug("CertificateRepository: getRandomNumber  randomNumber="+randomNumber);

        return randomNumber;
    }

    private BigInteger getRandomSerialNumber(BigInteger randomNumber) throws EBaseException {
        BigInteger nextSerialNumber = null;

        nextSerialNumber = randomNumber.add(mMinSerialNo);
        logger.debug("CertificateRepository: getRandomSerialNumber  nextSerialNumber="+nextSerialNumber);

        return nextSerialNumber;
    }

    private BigInteger checkSerialNumbers(BigInteger randomNumber, BigInteger serialNumber) throws EBaseException {
        BigInteger nextSerialNumber = null;
        BigInteger initialRandomNumber = randomNumber;
        BigInteger delta = BigInteger.ZERO;
        int i = 0;
        int n = mMaxCollisionRecoverySteps;

        do {
            logger.debug("CertificateRepository: checkSerialNumbers  checking("+(i+1)+")="+serialNumber);
            try {
                if (readCertificateRecord(serialNumber) != null) {
                    logger.debug("CertificateRepository: checkSerialNumbers  collision detected for serialNumber="+serialNumber);
                }
            } catch (EDBRecordNotFoundException nfe) {
                logger.debug("CertificateRepository: checkSerialNumbers  serial number "+serialNumber+" is available");
                nextSerialNumber = serialNumber;
            } catch (Exception e) {
                logger.warn("CertificateRepository: checkSerialNumbers: " + e.getMessage(), e);
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

    /**
     * Retrieves the next certificate serial number, and also increases
     * the serial number by one.
     *
     * @return serial number
     * @exception EBaseException failed to retrieve next serial number
     */
    @Override
    public synchronized BigInteger getNextSerialNumber()
            throws EBaseException {

        if (idGenerator == IDGenerator.RANDOM) {
            return super.getNextSerialNumber();
        }

        BigInteger nextSerialNumber = null;
        BigInteger randomNumber = null;

        initCache();
        logger.debug("CertificateRepository: getNextSerialNumber  mEnableRandomSerialNumbers="+mEnableRandomSerialNumbers);

        if (mEnableRandomSerialNumbers) {
            int i = 0;
            do {
                if (i > 0) {
                    logger.debug("CertificateRepository: getNextSerialNumber  regenerating serial number");
                }
                randomNumber = getRandomNumber();
                nextSerialNumber = getRandomSerialNumber(randomNumber);
                nextSerialNumber = checkSerialNumbers(randomNumber, nextSerialNumber);
                i++;
            } while (nextSerialNumber == null && i < mMaxCollisionRecoveryRegenerations);

            if (nextSerialNumber == null) {
                logger.error("CertificateRepository: in getNextSerialNumber  nextSerialNumber is null");
                throw new EBaseException( "nextSerialNumber is null" );
            }

            if (mCounter.compareTo(BigInteger.ZERO) >= 0 &&
                mMinSerialNo != null && mMaxSerialNo != null &&
                nextSerialNumber != null &&
                nextSerialNumber.compareTo(mMinSerialNo) >= 0 &&
                nextSerialNumber.compareTo(mMaxSerialNo) <= 0) {
                mCounter = mCounter.add(BigInteger.ONE);
            }
            logger.debug("CertificateRepository: getNextSerialNumber  nextSerialNumber="+
                      nextSerialNumber+"  mCounter="+mCounter);

            super.checkRange();
        } else {
            nextSerialNumber = super.getNextSerialNumber();
        }

        return nextSerialNumber;
    }

    @Override
    public BigInteger getRangeLength() {
        if (dbSubsystem.getEnableSerialMgmt() && mEnableRandomSerialNumbers) {
            return mMaxSerialNo.subtract(mMinSerialNo).add(BigInteger.ONE);
        }
        return null;
    }

    @Override
    public BigInteger getRandomLimit(BigInteger rangeLength) {
        if (dbSubsystem.getEnableSerialMgmt() && mEnableRandomSerialNumbers) {
            return rangeLength.subtract(mLowWaterMarkNo.shiftRight(1));
        }
        return null;
    }

    @Override
    public BigInteger getNumbersInRange() {
        if (dbSubsystem.getEnableSerialMgmt() && mEnableRandomSerialNumbers) {
            return mMaxSerialNo.subtract(mMinSerialNo).subtract(mCounter);
        }
        return super.getNumbersInRange();
    }

    public void updateCounter() {

        if (idGenerator == IDGenerator.RANDOM) {
            return;
        }

        logger.debug("CertificateRepository: Updating counter");
        logger.debug("CertificateRepository: - enable RSNv1: " + mEnableRandomSerialNumbers);
        logger.debug("CertificateRepository: - counter: " + mCounter);

        EngineConfig cs = engine.getConfig();

        try {
            initCache();
        } catch (Exception e) {
            logger.warn("CertificateRepository: updateCounter: " + e.getMessage(), e);
        }

        String crMode = dbSubsystem.getEntryAttribute(mBaseDN, RepositoryRecord.ATTR_DESCRIPTION, "", null);
        logger.debug("CertificateRepository: - mode: " + crMode);

        boolean modeChange = (mEnableRandomSerialNumbers && crMode != null && crMode.equals(PROP_SEQUENTIAL_MODE)) ||
                             ((!mEnableRandomSerialNumbers) && crMode != null && crMode.equals(PROP_RANDOM_MODE));
        logger.debug("CertificateRepository: - mode change: " + modeChange);

        if (modeChange) {
            if (mForceModeChange) {
                setEnableRandomSerialNumbers(mEnableRandomSerialNumbers, true, mForceModeChange);
            } else {
                setEnableRandomSerialNumbers(!mEnableRandomSerialNumbers, false, mForceModeChange);
            }

        } else if (mEnableRandomSerialNumbers && mCounter != null && mCounter.compareTo(BigInteger.ZERO) >= 0) {
            long t = System.currentTimeMillis();
            mDBConfig.putString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, mCounter + "," + t);
        }

        try {
            cs.commit(false);
        } catch (Exception e) {
            logger.warn("CertificateRepository: Unable to update CS.cfg: " + e.getMessage(), e);
        }

        logger.debug("CertificateRepository: - enable RSNv1: " + mEnableRandomSerialNumbers);
        logger.debug("CertificateRepository: - counter: " + mCounter);
    }

    private BigInteger getInRangeCount(String fromTime, BigInteger  minSerialNo, BigInteger maxSerialNo)
    throws EBaseException {
        BigInteger count = BigInteger.ZERO;
        String filter = null;

        if (fromTime != null && fromTime.length() > 0) {
            filter = "(certCreateTime >= "+fromTime+")";
        } else {
            filter = "(&("+CertRecord.ATTR_ID+">="+minSerialNo+")("+
                           CertRecord.ATTR_ID+"<="+maxSerialNo+"))";
        }
        logger.debug("CertificateRepository: getInRangeCount  filter="+filter+
                  "  minSerialNo="+minSerialNo+"  maxSerialNo="+maxSerialNo);

        Enumeration<Object> e = findCertRecs(filter, new String[] {CertRecord.ATTR_ID, "objectclass"});
        while (e != null && e.hasMoreElements()) {
            CertRecord rec = (CertRecord) e.nextElement();
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
        logger.debug("CertificateRepository: getInRangeCount  count=" + count);

        return count;
    }

    private BigInteger getInRangeCounter(BigInteger  minSerialNo, BigInteger maxSerialNo)
    throws EBaseException {

        EngineConfig cs = engine.getConfig();

        String c = null;
        String t = null;
        String s = (mDBConfig.getString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, "-1")).trim();
        logger.debug("CertificateRepository: getInRangeCounter:  saved counter string="+s);
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
        logger.debug("CertificateRepository: getInRangeCounter:  c="+c+"  t="+((t != null)?t:"null"));

        BigInteger counter = new BigInteger(c);
        BigInteger count = BigInteger.ZERO;
        if (engine.isPreOpMode()) {
            logger.debug("CertificateRepository: getInRangeCounter:  CMS.isPreOpMode");
            counter = new BigInteger("-2");
            mDBConfig.putString(PROP_RANDOM_SERIAL_NUMBER_COUNTER, "-2");
            try {
                cs.commit(false);
            } catch (Exception e) {
                logger.warn("CertificateRepository: getInRangeCounter: " + e.getMessage(), e);
            }
        } else if (t != null) {
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
        logger.debug("CertificateRepository: getInRangeCounter:  counter=" + counter);

        return counter;
    }

    @Override
    public BigInteger getLastSerialNumberInRange(BigInteger serial_low_bound, BigInteger serial_upper_bound)
            throws EBaseException {

        logger.debug("CertificateRepository:  in getLastSerialNumberInRange: low "
                + serial_low_bound + " high " + serial_upper_bound);

        if (serial_low_bound == null
                || serial_upper_bound == null || serial_low_bound.compareTo(serial_upper_bound) >= 0) {
            return null;

        }

        EngineConfig cs = engine.getConfig();

        mEnableRandomSerialNumbers = mDBConfig.getBoolean(PROP_ENABLE_RANDOM_SERIAL_NUMBERS, false);
        mForceModeChange = mDBConfig.getBoolean(PROP_FORCE_MODE_CHANGE, false);
        String crMode = dbSubsystem.getEntryAttribute(mBaseDN, RepositoryRecord.ATTR_DESCRIPTION, "", null);
        mMinRandomBitLength = mDBConfig.getInteger(PROP_MINIMUM_RANDOM_BITS, 4);
        mMaxCollisionRecoverySteps = mDBConfig.getInteger(PROP_COLLISION_RECOVERY_STEPS, 10);
        mMaxCollisionRecoveryRegenerations = mDBConfig.getInteger(PROP_COLLISION_RECOVERY_REGENERATIONS, 3);
        boolean modeChange = (mEnableRandomSerialNumbers && crMode != null && crMode.equals(PROP_SEQUENTIAL_MODE)) ||
                             ((!mEnableRandomSerialNumbers) && crMode != null && crMode.equals(PROP_RANDOM_MODE));
        boolean enableRsnAtConfig = mEnableRandomSerialNumbers && engine.isPreOpMode() &&
                                    (crMode == null || crMode.length() == 0);
        logger.debug("CertificateRepository: getLastSerialNumberInRange"+
                  "  mEnableRandomSerialNumbers="+mEnableRandomSerialNumbers+
                  "  mMinRandomBitLength="+mMinRandomBitLength+
                  "  CollisionRecovery="+mMaxCollisionRecoveryRegenerations+","+mMaxCollisionRecoverySteps);
        logger.debug("CertificateRepository: getLastSerialNumberInRange  modeChange="+modeChange+
                  "  enableRsnAtConfig="+enableRsnAtConfig+"  mForceModeChange="+mForceModeChange+
                  ((crMode != null)?"  mode="+crMode:""));
        if (modeChange || enableRsnAtConfig) {
            if (mForceModeChange || enableRsnAtConfig) {
                setCertificateRepositoryMode((mEnableRandomSerialNumbers)? PROP_RANDOM_MODE: PROP_SEQUENTIAL_MODE);
                if (mForceModeChange) {
                    mForceModeChange = false;
                    mDBConfig.remove(PROP_FORCE_MODE_CHANGE);
                }
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
            cs.commit(false);
        } catch (Exception e) {
        }
        logger.debug("CertificateRepository: getLastSerialNumberInRange  mEnableRandomSerialNumbers="+mEnableRandomSerialNumbers);

        String ldapfilter = "("+CertRecord.ATTR_CERT_STATUS+"=*"+")";

        String[] attrs = null;

        CertRecordList recList = findCertRecordsInList(ldapfilter, attrs, serial_upper_bound.toString(10), "serialno", 5 * -1);

        int size = recList.getSize();

        logger.debug("CertificateRepository:getLastSerialNumberInRange: recList size " + size);

        if (size <= 0) {
            logger.debug("CertificateRepository:getLastSerialNumberInRange: index may be empty");

            BigInteger ret = new BigInteger(serial_low_bound.toString(10));

            ret = ret.subtract(BigInteger.ONE);
            logger.debug("CertificateRepository:getLastCertRecordSerialNo: returning " + ret);
            return ret;
        }
        int ltSize = recList.getSizeBeforeJumpTo();

        logger.debug("CertificateRepository:getLastSerialNumberInRange: ltSize " + ltSize);

        CertRecord curRec = null;

        int i;
        Object obj = null;

        for (i = 0; i < 5; i++) {
            obj = recList.getCertRecord(i);

            if (obj != null) {
                curRec = (CertRecord) obj;

                BigInteger serial = curRec.getSerialNumber();

                logger.debug("CertificateRepository:getLastCertRecordSerialNo:  serialno  " + serial);

                if (((serial.compareTo(serial_low_bound) == 0) || (serial.compareTo(serial_low_bound) == 1)) &&
                        ((serial.compareTo(serial_upper_bound) == 0) || (serial.compareTo(serial_upper_bound) == -1))) {
                    logger.debug("getLastSerialNumberInRange returning: " + serial);
                    if (modeChange && mEnableRandomSerialNumbers) {
                        mCounter = serial.subtract(serial_low_bound).add(BigInteger.ONE);
                        logger.debug("getLastSerialNumberInRange mCounter: " + mCounter);
                    }
                    return serial;
                }
            } else {
                logger.warn("getLastSerialNumberInRange:found null from getCertRecord");
            }
        }

        BigInteger ret = new BigInteger(serial_low_bound.toString(10));

        ret = ret.subtract(BigInteger.ONE);

        logger.debug("CertificateRepository:getLastCertRecordSerialNo: returning " + ret);
        if (modeChange && mEnableRandomSerialNumbers) {
            mCounter = BigInteger.ZERO;
            logger.debug("getLastSerialNumberInRange mCounter: " + mCounter);
        }
        return ret;

    }

    /**
     * Removes certificate records with this repository.
     *
     * @param beginS BigInteger with radix 16
     * @param endS BigInteger with radix 16
     */
    public void removeCertRecords(BigInteger beginS, BigInteger endS) throws EBaseException {
        String filter = "(" + CertRecord.ATTR_CERT_STATUS + "=*" + ")";
        CertRecordList list = findCertRecordsInList(filter, null, "serialno", 10);
        int size = list.getSize();
        Enumeration<CertRecord> e = list.getCertRecords(0, size - 1);
        while (e.hasMoreElements()) {
            CertRecord rec = e.nextElement();
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

    public CertRecord createCertRecord(
            RequestId requestID,
            String profileIDMapping,
            X509CertImpl cert) throws Exception {

        CertId certID = new CertId(cert.getSerialNumber());

        MetaInfo meta = new MetaInfo();
        meta.set(CertRecord.META_REQUEST_ID, requestID.toString());
        meta.set(CertRecord.META_PROFILE_ID, profileIDMapping);

        return new CertRecord(cert.getSerialNumber(), cert, meta);
    }

    /**
     * Adds a certificate record to the repository. Each certificate
     * record contains four parts: certificate, meta-attributes,
     * issue information and revocation information.
     *
     * @param record X.509 certificate
     * @exception EBaseException failed to add new certificate to
     *                the repository
     */
    public void addCertificateRecord(CertRecord record) throws EBaseException {

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn=" + record.getSerialNumber() + "," + mBaseDN;
            logger.debug("CertificateRepository: Adding certificate record " + name);

            X509CertImpl x509cert = (X509CertImpl) record.get(CertRecord.ATTR_X509CERT);
            logger.debug("CertificateRepository: - subject: " + x509cert.getSubjectName());
            logger.debug("CertificateRepository: - issuer: " + x509cert.getIssuerName());

            SessionContext ctx = SessionContext.getContext();
            String uid = (String) ctx.get(SessionContext.USER_ID);

            if (uid == null) {
                // XXX is this right?
                uid = "system";
                // logger.error("XXX servlet should set USER_ID");
                // throw new EBaseException(BaseResources.UNKNOWN_PRINCIPAL_1, "null");
            }

            record.set(CertRecord.ATTR_ISSUED_BY, uid);
            logger.debug("CertificateRepository: - issued by: " + uid);

            // Check validity of this certificate. If it is not invalid,
            // mark it so. We will have a thread to transit the status
            // from INVALID to VALID.

            Date now = new Date();

            String status = (String) record.get(CertRecord.ATTR_CERT_STATUS);
            if (x509cert.getNotBefore().after(now)) {
                // not yet valid
                status = CertRecord.STATUS_INVALID;
                record.set(CertRecord.ATTR_CERT_STATUS, status);
            }
            logger.debug("CertificateRepository: - status: " + status);

            s.add(name, record);

        } catch (EBaseException e) {
            throw new EBaseException("Unable to add certificate record: " + e.getMessage(), e);

        }
    }

    /**
     * Used by the Clone Master (CLA) to add a revoked certificate
     * record to the repository.
     * <p>
     *
     * @param record a CertRecord
     * @exception EBaseException failed to add new certificate to
     *                the repository
     */
    public void addRevokedCertRecord(CertRecord record)
            throws EBaseException {

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn=" + record.getSerialNumber() + "," + mBaseDN;

            s.add(name, record);
        }
    }

    public void updateStatus(Vector<CertId> list, String status) throws EBaseException {

        for (int i = 0; i < list.size(); i++) {
            CertId certID = list.elementAt(i);
            updateStatus(certID, status);
        }
    }

    /**
     * Reads the certificate identified by the given serial no.
     *
     * @param serialNo serial number of certificate
     * @return certificate
     * @exception EBaseException failed to retrieve certificate
     */
    public X509CertImpl getX509Certificate(BigInteger serialNo)
            throws EBaseException {
        CertRecord cr = readCertificateRecord(serialNo);

        return (cr.getCertificate());
    }

    /**
     * Deletes certificate from this repository.
     *
     * @param serialNo serial number of certificate
     * @exception EBaseException failed to delete
     */
    public void deleteCertificateRecord(BigInteger serialNo)
            throws EBaseException {

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn=" + serialNo + "," + mBaseDN;
            s.delete(name);
        }
    }

    /**
     * Reads certificate from repository.
     *
     * @param serialNo serial number of certificate
     * @return certificate record
     * @exception EBaseException failed to retrieve certificate
     */
    public CertRecord readCertificateRecord(BigInteger serialNo)
            throws EBaseException {
        CertRecord rec = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn=" + serialNo + "," + mBaseDN;

            rec = (CertRecord) s.read(name);
        }
        return rec;
    }

    public boolean checkCertificateRecord(BigInteger serialNo)
        throws EBaseException {
        CertRecord rec = null;
        boolean exists = true;

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn=" + serialNo + "," + mBaseDN;
            String attrs[] = { "DN" };

            rec = (CertRecord) s.read(name, attrs);
            if (rec == null) exists = false;
        } catch (EDBRecordNotFoundException e) {
            exists = false;
        } catch (Exception e) {
            throw new EBaseException(e.getMessage());
        }
        return exists;
    }

    private void setCertificateRepositoryMode(String mode) {
        DBSSession s = null;

        logger.debug("CertificateRepository: setCertificateRepositoryMode   setting mode: "+mode);
        try {
            s = dbSubsystem.createSession();
            ModificationSet mods = new ModificationSet();
            mods.add(RepositoryRecord.ATTR_DESCRIPTION, Modification.MOD_REPLACE, mode);
            s.modify(mBaseDN, mods);
        } catch (Exception e) {
            logger.warn("CertificateRepository: setCertificateRepositoryMode: " + e.getMessage(), e);
        }
        try {
            if (s != null) s.close();
        } catch (Exception e) {
            logger.warn("CertificateRepository: setCertificateRepositoryMode: " + e.getMessage(), e);
        }
    }

    /**
     * Modifies certificate record.
     *
     * @param serialNo serial number of record
     * @param mods modifications
     * @exception EBaseException failed to modify
     */
    public synchronized void modifyCertificateRecord(BigInteger serialNo,
            ModificationSet mods) throws EBaseException {

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn=" + serialNo + "," + mBaseDN;

            mods.add(CertRecord.ATTR_MODIFY_TIME, Modification.MOD_REPLACE,
                    new Date());
            s.modify(name, mods);
        }
    }

    /**
     * Checks if the certificate exists in this repository.
     *
     * @param serialNo serial number of certificate
     * @return true if it exists
     * @exception EBaseException failed to check
     */
    public boolean containsCertificate(BigInteger serialNo)
            throws EBaseException {
        try {
            CertRecord cr = readCertificateRecord(serialNo);

            if (cr != null)
                return true;
        } catch (EBaseException e) {
        }
        return false;
    }

    /**
     * Marks certificate as revoked.
     *
     * isAlreadyRevoked - boolean to indicate that the cert was revoked
     * ( possibly onHold )
     * When a cert was originally revoked (possibly onHold),
     * some of the ldap attributes already exist,
     * so "MOD_REPLACE" is needed instead of "MOD_ADD"
     *
     * @param id serial number
     * @param info revocation information
     * @exception EBaseException failed to mark
     */
    public void markAsRevoked(BigInteger id, RevocationInfo info)
            throws EBaseException {
        markAsRevoked(id, info, false);
    }

    /**
     * Marks certificate as revoked.
     *
     * @param id serial number
     * @param info revocation information
     * @param isAlreadyRevoked boolean to indicate if the cert was revoked onHold
     * @exception EBaseException failed to mark
     */
    public void markAsRevoked(BigInteger id, RevocationInfo info, boolean isAlreadyRevoked)
            throws EBaseException {
        ModificationSet mods = new ModificationSet();
        if (isAlreadyRevoked) {
            mods.add(CertRecord.ATTR_REVO_INFO, Modification.MOD_REPLACE, info);
        } else {
            mods.add(CertRecord.ATTR_REVO_INFO, Modification.MOD_ADD, info);
        }
        SessionContext ctx = SessionContext.getContext();
        String uid = (String) ctx.get(SessionContext.USER_ID);

        /*
         * When already revoked onHold, the fields already existing in record
         * can only be replaced instead of added
         */
        if (isAlreadyRevoked) {
            if (uid == null) {
                mods.add(CertRecord.ATTR_REVOKED_BY, Modification.MOD_REPLACE,
                        "system");
            } else {
                mods.add(CertRecord.ATTR_REVOKED_BY, Modification.MOD_REPLACE,
                        uid);
            }
            mods.add(CertRecord.ATTR_REVOKED_ON, Modification.MOD_REPLACE,
                    new Date());
        } else {
            if (uid == null) {
                mods.add(CertRecord.ATTR_REVOKED_BY, Modification.MOD_ADD,
                        "system");
            } else {
                mods.add(CertRecord.ATTR_REVOKED_BY, Modification.MOD_ADD,
                        uid);
            }
            mods.add(CertRecord.ATTR_REVOKED_ON, Modification.MOD_ADD,
                    new Date());
            mods.add(CertRecord.ATTR_CERT_STATUS, Modification.MOD_REPLACE,
                    CertRecord.STATUS_REVOKED);
        }

        modifyCertificateRecord(id, mods);
    }

    /**
     * Unmark a revoked certificates.
     *
     * @param id serial number
     * @param info revocation information
     * @param revokedOn revocation date
     * @param revokedBy userid
     * @exception EBaseException failed to unmark
     */
    public void unmarkRevoked(BigInteger id, RevocationInfo info,
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
     * Updates certificate status.
     *
     * @param id serial number
     * @param status certificate status
     * @exception EBaseException failed to update status
     */
    public void updateStatus(CertId id, String status) throws EBaseException {

        logger.info("CertificateRepository: Updating cert " + id.toHexString() + " status to " + status);

        ModificationSet mods = new ModificationSet();
        mods.add(CertRecord.ATTR_CERT_STATUS, Modification.MOD_REPLACE, status);

        modifyCertificateRecord(id.toBigInteger(), mods);
    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param maxSize max size to return
     * @param sortAttribute Attribute of CertRecord to sort the results
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<Object> searchCertificates(String filter, int maxSize,String sortAttribute)
            throws EBaseException {

        Enumeration<Object> e = null;

        logger.debug("searchCertificates filter " + filter + " maxSize " + maxSize);
        try (DBSSession s = dbSubsystem.createSession()) {
            e = s.search(mBaseDN, filter, maxSize,sortAttribute);
        }
        return e;
    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     * Here is a list of filter
     * attribute can be used:
     *
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
     *
     * The filter should follow RFC1558 LDAP filter syntax.
     * For example,
     *
     * {@Code (&(certRecordId=5)(x509Cert.notBefore=934398398))}
     *
     * @param filter search filter
     * @param maxSize max size to return
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<Object> searchCertificates(String filter, int maxSize)
            throws EBaseException {
        Enumeration<Object> e = null;

        logger.debug("searchCertificates filter " + filter + " maxSize " + maxSize);
        try (DBSSession s = dbSubsystem.createSession()) {
            e = s.search(mBaseDN, filter, maxSize);
        }
        return e;
    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param maxSize max size to return
     * @param timeLimit timeout value
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<CertRecord> searchCertificates(String filter, int maxSize, int timeLimit)
            throws EBaseException {

        Vector<CertRecord> v = new Vector<>();

        logger.debug("searchCertificateswith time limit filter " + filter);
        try (DBSSession s = dbSubsystem.createSession()) {
            DBSearchResults sr = s.search(mBaseDN, filter, maxSize, timeLimit);
            while (sr.hasMoreElements()) {
                v.add((CertRecord) sr.nextElement());
            }
        }
        return v.elements();
    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param maxSize max size to return
     * @param timeLimit timeout value
     * @param sortAttribute Attribute of CertRecord to sort the results
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<CertRecord> searchCertificates(String filter, int maxSize,
            int timeLimit,String sortAttribute) throws EBaseException {

        Vector<CertRecord> v = new Vector<>();

        logger.debug("searchCertificateswith time limit filter " + filter);
        try (DBSSession s = dbSubsystem.createSession()) {
            DBSearchResults sr = s.search(mBaseDN, filter, maxSize, timeLimit,sortAttribute);
            while (sr.hasMoreElements()) {
                v.add((CertRecord) sr.nextElement());
            }
        }
        return v.elements();

    }


    /**
     * Finds certificate records.
     *
     * @deprecated replaced by <code>findCertificatesInList</code>
     *
     * @param filter search filter
     * @return a list of certificate records
     * @exception EBaseException failed to retrieve cert records
     */
    @Deprecated
    public Enumeration<Object> findCertRecs(String filter)
            throws EBaseException {
        logger.debug("findCertRecs " + filter);
        Enumeration<Object> e = null;
        try (DBSSession s = dbSubsystem.createSession()) {
            e = s.search(mBaseDN, filter);
        }
        return e;
    }

    public Enumeration<Object> findCertRecs(String filter, String[] attrs)
            throws EBaseException {

        logger.debug("findCertRecs " + filter
                 + "attrs " + Arrays.toString(attrs));
        Enumeration<Object> e = null;
        try (DBSSession s = dbSubsystem.createSession()) {
            e = s.search(mBaseDN, filter, attrs);
        }
        return e;

    }

    /**
     * Finds all certificates given a filter.
     *
     * @param filter search filter
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<X509CertImpl> findCertificates(String filter)
            throws EBaseException {
        Enumeration<CertRecord> e = findCertRecords(filter);
        Vector<X509CertImpl> v = new Vector<>();

        while (e.hasMoreElements()) {
            CertRecord rec = e.nextElement();

            v.addElement(rec.getCertificate());
        }
        return v.elements();
    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     * If you are going to process everything in the list,
     * use this.
     *
     * @param filter search filter
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<CertRecord> findCertRecords(String filter)
            throws EBaseException {
        Enumeration<CertRecord> e = null;

        CertRecordList list = findCertRecordsInList(filter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);
        return e;
    }

    /**
     * Finds certificate records. Here is a list of filter
     * attribute can be used:
     *
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
     *
     * The filter should follow RFC1558 LDAP filter syntax.
     * For example,
     *
     * {@Code (&(certRecordId=5)(x509Cert.notBefore=934398398))}
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param pageSize page size
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public CertRecordList findCertRecordsInList(String filter,
            String attrs[], int pageSize) throws EBaseException {
        return findCertRecordsInList(filter, attrs, CertRecord.ATTR_ID,
                pageSize);
    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param sortKey key to use for sorting the returned elements
     * @param pageSize page size
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public CertRecordList findCertRecordsInList(String filter,
            String attrs[], String sortKey, int pageSize)
            throws EBaseException {

        logger.debug("CertificateRepository.findCertRecordsInList()");

        try (DBSSession session = dbSubsystem.createSession()) {
            DBVirtualList<CertRecord> list = session.<CertRecord>createVirtualList(
                    mBaseDN,
                    filter,
                    attrs,
                    sortKey,
                    pageSize);

            return new CertRecordList(list);
        }
    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param jumpTo jump to index
     * @param sortKey key to use for sorting the returned elements
     * @param pageSize page size
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public CertRecordList findCertRecordsInList(String filter,
            String attrs[], String jumpTo, String sortKey, int pageSize)
            throws EBaseException {
        return findCertRecordsInList(filter, attrs, jumpTo, false, sortKey, pageSize);

    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param jumpTo jump to index
     * @param hardJumpTo
     * @param sortKey key to use for sorting the returned elements
     * @param pageSize page size
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public CertRecordList findCertRecordsInList(String filter,
            String attrs[], String jumpTo, boolean hardJumpTo,
                         String sortKey, int pageSize)
            throws EBaseException {
        CertRecordList list = null;

        logger.debug("In findCertRecordsInList with Jumpto " + jumpTo);
        try (DBSSession s = dbSubsystem.createSession()) {
            String jumpToVal = null;

            if (hardJumpTo) {
                logger.debug("In findCertRecordsInList with hardJumpto ");
                jumpToVal = "99";
            } else {
                int len = jumpTo.length();

                if (len > 9) {
                    jumpToVal = Integer.toString(len) + jumpTo;
                } else {
                    jumpToVal = "0" + Integer.toString(len) + jumpTo;
                }
            }

            DBVirtualList<CertRecord> vlist = s.createVirtualList(
                    mBaseDN,
                    filter,
                    attrs,
                    jumpToVal,
                    sortKey,
                    pageSize);

            list = new CertRecordList(vlist);
        }
        return list;
    }

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param jumpTo jump to index
     * @param sortKey key to use for sorting the returned elements
     * @param pageSize page size
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public CertRecordList findCertRecordsInListRawJumpto(String filter,
            String attrs[], String jumpTo, String sortKey, int pageSize)
            throws EBaseException {
        CertRecordList list = null;

        logger.debug("In findCertRecordsInListRawJumpto with Jumpto " + jumpTo);

        try (DBSSession s = dbSubsystem.createSession()) {

            DBVirtualList<CertRecord> vlist = s.createVirtualList(
                    mBaseDN,
                    filter,
                    attrs,
                    jumpTo,
                    sortKey,
                    pageSize);

            list = new CertRecordList(vlist);
        }
        return list;
    }

    /**
     * Marks certificate as renewable.
     *
     * @param record certificate record to modify
     * @exception EBaseException failed to update
     */
    public void markCertificateAsRenewable(CertRecord record)
            throws EBaseException {
        changeRenewalAttribute(record.getSerialNumber().toString(),
                CertRecord.AUTO_RENEWAL_ENABLED);
    }

    /**
     * Marks certificate as not renewable.
     *
     * @param record certificate record to modify
     * @exception EBaseException failed to update
     */
    public void markCertificateAsNotRenewable(CertRecord record)
            throws EBaseException {
        changeRenewalAttribute(record.getSerialNumber().toString(),
                CertRecord.AUTO_RENEWAL_DISABLED);
    }

    /**
     * Marks certificate as renewed.
     *
     * @param serialNo certificate record to modify
     * @exception EBaseException failed to update
     */
    public void markCertificateAsRenewed(String serialNo)
            throws EBaseException {
        changeRenewalAttribute(serialNo, CertRecord.AUTO_RENEWAL_DONE);
    }

    /**
     * Marks certificate as renewed and notified.
     *
     * @param serialNo certificate record to modify
     * @exception EBaseException failed to update
     */
    public void markCertificateAsRenewalNotified(String serialNo)
            throws EBaseException {
        changeRenewalAttribute(serialNo, CertRecord.AUTO_RENEWAL_NOTIFIED);
    }

    private void changeRenewalAttribute(String serialno, String value)
            throws EBaseException {

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn=" + serialno + "," + mBaseDN;
            ModificationSet mods = new ModificationSet();

            mods.add(CertRecord.ATTR_AUTO_RENEW, Modification.MOD_REPLACE,
                    value);
            s.modify(name, mods);
        }
    }

    /**
     * Retrieves renewable certificates.
     *
     * @param renewalTime renewal time
     * @return certificates
     * @exception EBaseException failed to retrieve
     */
    public Hashtable<String, RenewableCertificateCollection> getRenewableCertificates(String renewalTime)
            throws EBaseException {

        Hashtable<String, RenewableCertificateCollection> tab = null;

        String filter = "(&(" + CertRecord.ATTR_CERT_STATUS + "=" +
                CertRecord.STATUS_VALID + ")("
                + CertRecord.ATTR_X509CERT +
                "." + CertificateValidity.NOT_AFTER + "<=" + renewalTime +
                ")(!(" + CertRecord.ATTR_AUTO_RENEW + "=" +
                CertRecord.AUTO_RENEWAL_DONE +
                "))(!(" + CertRecord.ATTR_AUTO_RENEW + "=" +
                CertRecord.AUTO_RENEWAL_NOTIFIED + ")))";

        CertRecordList list = findCertRecordsInList(filter, null, "serialno", 10);
        int size = list.getSize();
        Enumeration<CertRecord> e = list.getCertRecords(0, size - 1);

        tab = new Hashtable<>();
        while (e.hasMoreElements()) {
            CertRecord rec = e.nextElement();
            X509CertImpl cert = rec.getCertificate();
            String subjectDN = cert.getSubjectName().toString();
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
        return tab;
    }

    /**
     * Gets all valid and unexpired certificates pertaining
     * to a subject DN.
     *
     * @param subjectDN The distinguished name of the subject.
     * @param validityType The type of certificates to get.
     * @return An array of certificates.
     * @throws EBaseException on error.
     */

    public X509CertImpl[] getX509Certificates(String subjectDN,
            int validityType) throws EBaseException {

        X509CertImpl certs[] = null;

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

        CertRecordList list = findCertRecordsInList(filter, null, "serialno", 10);
        int size = list.getSize();
        Enumeration<CertRecord> e = list.getCertRecords(0, size - 1);

        Vector<X509CertImpl> v = new Vector<>();

        while (e.hasMoreElements()) {
            CertRecord rec = e.nextElement();

            v.addElement(rec.getCertificate());
        }
        if (v.size() == 0)
            return null;
        certs = new X509CertImpl[v.size()];
        v.copyInto(certs);
        return certs;
    }

    public X509CertImpl[] getX509Certificates(String filter)
            throws EBaseException {

        X509CertImpl certs[] = null;

        Enumeration<CertRecord> e = null;

        if (filter != null && filter.length() > 0) {
            CertRecordList list = findCertRecordsInList(filter, null, "serialno", 10);
            int size = list.getSize();

            e = list.getCertRecords(0, size - 1);
        }

        Vector<X509CertImpl> v = new Vector<>();

        while (e != null && e.hasMoreElements()) {
            CertRecord rec = e.nextElement();

            v.addElement(rec.getCertificate());
        }
        if (v.size() > 0) {
            certs = new X509CertImpl[v.size()];
            v.copyInto(certs);
        }
        return certs;
    }

    /**
     * Retrieves valid certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<CertRecord> getValidCertificates(String from, String to)
            throws EBaseException {
        Vector<CertRecord> v = new Vector<>();

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

        CertRecordList list = findCertRecordsInList(ldapfilter, null, fromVal, "serialno", 40);

        BigInteger toInt = null;
        if (to != null && !to.trim().equals("")) {
            toInt = new BigInteger(to);
        }

        for (int i = 0;; i++) {
            CertRecord rec = list.getCertRecord(i);
            logger.debug("processing record: " + i);
            if (rec == null) {
                break; // no element returned
            }
            logger.debug("processing record: " + i + " " + rec.getSerialNumber());
            // Check if we are past the 'to' marker
            if (toInt != null) {
                if (rec.getSerialNumber().compareTo(toInt) > 0) {
                    break;
                }
            }
            v.addElement(rec);
        }

        logger.debug("returning " + v.size() + " elements");
        return v.elements();
    }

    /**
     * Retrives all valid certificates excluding ones already revoked.
     */
    public Enumeration<CertRecord> getAllValidCertificates()
            throws EBaseException {
        Enumeration<CertRecord> e = null;

        Date now = new Date();
        String ldapfilter = "(&(!(" + CertRecord.ATTR_REVO_INFO + "=*))(" +
                CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_BEFORE + "<=" +
                DateMapper.dateToDB(now) + ")(" +
                CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_AFTER + ">=" +
                DateMapper.dateToDB(now) + "))";
        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);

        // XXX - transaction is not done at this moment
        return e;
    }

    /**
     * Retrieves valid and not published certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<CertRecord> getValidNotPublishedCertificates(String from, String to)
            throws EBaseException {
        Enumeration<CertRecord> e = null;

        Date now = new Date();
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

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);

        return e;
    }

    /**
     * Retrives all valid not published certificates
     * excluding ones already revoked.
     */
    public Enumeration<CertRecord> getAllValidNotPublishedCertificates()
            throws EBaseException {
        Enumeration<CertRecord> e = null;

        Date now = new Date();
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
        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);

        return e;
    }

    /**
     * Retrieves expired certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<CertRecord> getExpiredCertificates(String from, String to)
            throws EBaseException {

        Enumeration<CertRecord> e = null;

        Date now = new Date();
        String ldapfilter = "(&(";

        if (from != null && from.length() > 0)
            ldapfilter += CertRecord.ATTR_ID + ">=" + from + ")(";
        if (to != null && to.length() > 0)
            ldapfilter += CertRecord.ATTR_ID + "<=" + to + ")(";
        ldapfilter += "!(" + CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_AFTER + ">=" +
                DateMapper.dateToDB(now) + ")))";

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);
        return e;
    }

    /**
     * Retrives all expired certificates.
     */
    public Enumeration<CertRecord> getAllExpiredCertificates()
            throws EBaseException {

        Enumeration<CertRecord> e = null;

        Date now = new Date();
        String ldapfilter = "(!(" + CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_AFTER + ">=" +
                DateMapper.dateToDB(now) + "))";

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);

        return e;
    }

    /**
     * Retrieves expired and published certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<CertRecord> getExpiredPublishedCertificates(String from, String to)
            throws EBaseException {

        Enumeration<CertRecord> e = null;

        Date now = new Date();
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

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);

        return e;
    }

    /**
     * Retrives all expired publishedcertificates.
     */
    public Enumeration<CertRecord> getAllExpiredPublishedCertificates()
            throws EBaseException {

        Enumeration<CertRecord> e = null;

        Date now = new Date();
        String ldapfilter = "(&";

        ldapfilter += "(!(" + CertRecord.ATTR_X509CERT + "." +
                CertificateValidity.NOT_AFTER + ">=" +
                DateMapper.dateToDB(now) + "))";
        ldapfilter += "(certMetainfo=" +
                CertRecord.META_LDAPPUBLISH +
                ":true))";

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);

        return e;
    }

    /**
     * Gets Invalid certs orderes by noAfter date, jumps to records
     * where notAfter date is greater than current.
     *
     * @param date reference date
     * @param pageSize page size
     * @return a list of certificate records
     * @exception EBaseException failed to retrieve
     */
    public CertRecordList getInvalidCertsByNotBeforeDate(Date date, int pageSize)
            throws EBaseException {

        CertRecordList list = null;

        String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_INVALID + ")";

        String[] attrs = null;

        if (mConsistencyCheck == false) {
            attrs = new String[] { "objectclass", CertRecord.ATTR_ID, CertRecord.ATTR_X509CERT };
        }

        logger.debug("getInvalidCertificatesByNotBeforeDate filter " + ldapfilter);

        logger.debug("getInvalidCertificatesByNotBeforeDate: about to call findCertRecordsInList");

        list = findCertRecordsInListRawJumpto(ldapfilter, attrs,
                    DateMapper.dateToDB(date), "notBefore", pageSize);


        return list;

    }

    /**
     * Gets valid certs orderes by noAfter date, jumps to records
     * where notAfter date is greater than current.
     *
     * @param date reference date
     * @param pageSize page size
     * @return a list of certificate records
     * @exception EBaseException failed to retrieve
     */
    public CertRecordList getValidCertsByNotAfterDate(Date date, int pageSize)
            throws EBaseException {

        CertRecordList list = null;

        String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_VALID + ")";

        String[] attrs = null;

        if (mConsistencyCheck == false) {
            attrs = new String[] { "objectclass", CertRecord.ATTR_ID, CertRecord.ATTR_X509CERT };
        }

        logger.debug("getValidCertsByNotAfterDate filter " + ldapfilter);

        list = findCertRecordsInListRawJumpto(ldapfilter, attrs, DateMapper.dateToDB(date), "notAfter", pageSize);

        return list;
    }

    /**
     * Gets Revoked certs orderes by noAfter date, jumps to records
     * where notAfter date is greater than current.
     *
     * @param date reference date
     * @param pageSize page size
     * @return a list of certificate records
     * @exception EBaseException failed to retrieve
     */
    public CertRecordList getRevokedCertsByNotAfterDate(Date date, int pageSize)
            throws EBaseException {

        CertRecordList list = null;

        String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")";

        String[] attrs = null;

        if (mConsistencyCheck == false) {
            attrs = new String[] { "objectclass", CertRecord.ATTR_REVOKED_ON, CertRecord.ATTR_ID,
                        CertRecord.ATTR_REVO_INFO, CertificateValidity.NOT_AFTER, CertRecord.ATTR_X509CERT };
        }

        logger.debug("getRevokedCertificatesByNotAfterDate filter " + ldapfilter);

        logger.debug("getRevokedCertificatesByNotAfterDate: about to call findCertRecordsInList");

        list = findCertRecordsInListRawJumpto(ldapfilter, attrs,
                    DateMapper.dateToDB(date), "notafter", pageSize);

        return list;

    }

    /**
     * Retrieves revoked certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<CertRecord> getRevokedCertificates(String from, String to)
            throws EBaseException {

        Enumeration<CertRecord> e = null;

        String ldapfilter = "(&(" + CertRecord.ATTR_REVO_INFO + "=*)";

        if (from != null && from.length() > 0)
            ldapfilter += "(" + CertRecord.ATTR_ID + ">=" + from + ")";
        if (to != null && to.length() > 0)
            ldapfilter += "(" + CertRecord.ATTR_ID + "<=" + to + ")";
        ldapfilter += ")";

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);
        return e;
    }

    /**
    * Retrieves all revoked certificates including ones that have expired
     * or that are not yet valid.
     *
     * @return a list of revoked certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<CertRecord> getAllRevokedCertificates()
            throws EBaseException {
        Enumeration<CertRecord> e = null;
        // index is setup for this filter
        String ldapfilter = "(|(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")("
                + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED_EXPIRED + "))";

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);

        return e;
    }

    /**
     * Retrieves revoked and published certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<CertRecord> getRevokedPublishedCertificates(String from, String to)
            throws EBaseException {
        Enumeration<CertRecord> e = null;

        String ldapfilter = "(&(" + CertRecord.ATTR_REVO_INFO + "=*)";

        if (from != null && from.length() > 0)
            ldapfilter += "(" + CertRecord.ATTR_ID + ">=" + from + ")";
        if (to != null && to.length() > 0)
            ldapfilter += "(" + CertRecord.ATTR_ID + "<=" + to + ")";
        ldapfilter += "(certMetainfo=" +
                CertRecord.META_LDAPPUBLISH +
                ":true))";

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);
        return e;
    }

    /**
     * Retrives all revoked published certificates including ones
     * already expired or not yet valid.
     */
    public Enumeration<CertRecord> getAllRevokedPublishedCertificates()
            throws EBaseException {

        Enumeration<CertRecord> e = null;
        // index is setup for this filter
        String ldapfilter = "(&(|(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")("
                + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED_EXPIRED + "))";

        ldapfilter += "(certMetainfo=" +
                CertRecord.META_LDAPPUBLISH +
                ":true))";

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);
        return e;
    }

    /**
     * Retrieves all revoked certificates that have not expired.
     *
     * @param asOfDate as of date
     * @return a list of revoked certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<CertRecord> getRevokedCertificates(Date asOfDate)
            throws EBaseException {

        Enumeration<CertRecord> e = null;

        String ldapfilter = "(&(" +
                CertRecord.ATTR_REVO_INFO + "=*)(" + CertRecord.ATTR_X509CERT +
                "." + CertificateValidity.NOT_AFTER + " >= " +
                DateMapper.dateToDB(asOfDate) + "))";
        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);
        return e;
    }

    /**
     * Retrieves all revoked but not expired certificates.
     *
     * @return a list of revoked certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<CertRecord> getAllRevokedNonExpiredCertificates()
            throws EBaseException {

        Enumeration<CertRecord> e = null;
        String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")"; // index is setup for this filter

        CertRecordList list = findCertRecordsInList(ldapfilter, null, "serialno", 10);
        int size = list.getSize();

        e = list.getCertRecords(0, size - 1);
        return e;
    }

    LDAPSearchResults searchForModifiedCertificateRecords(DBSSession session) throws EBaseException {
        logger.debug("Starting persistent search.");
        String filter = "(" + CertRecord.ATTR_CERT_STATUS + "=*)";
        return session.persistentSearch(mBaseDN, filter, null);
    }

    /**
     * Checks if the presented certificate belongs to the repository
     * and is revoked.
     *
     * @param cert certificate to verify.
     * @return RevocationInfo if the presented certificate is revoked otherwise null.
     */
    public RevocationInfo isCertificateRevoked(X509CertImpl cert)
            throws EBaseException {

        // 615932
        if (cert == null) {
            logger.warn("CertificateRepository: Missing certificate");
            return null;
        }

        logger.debug("CertificateRepository: Checking revocation status for cert " + cert.getSerialNumber());
        CertRecord rec = readCertificateRecord(cert.getSerialNumber());

        if (rec == null) {
            logger.debug("CertificateRepository: Unknown certificate");
            return null;
        }

        if (!rec.getStatus().equals(CertRecord.STATUS_REVOKED)) {
            logger.debug("CertificateRepository: Certificate not revoked");
            return null;
        }

        X500Name name = cert.getSubjectName();
        X500Name repCertName = rec.getCertificate().getSubjectName();

        if (!name.equals(repCertName)) {
            logger.debug("CertificateRepository: Certificate subjects do not match");
            return null;
        }

        byte[] certEncoded = null;
        byte[] repCertEncoded = null;

        try {
            certEncoded = cert.getEncoded();
            repCertEncoded = rec.getCertificate().getEncoded();
        } catch (Exception e) {
            logger.warn("Unable to parse certificate: " + e.getMessage(), e);
        }

        if (certEncoded == null || repCertEncoded == null) {
            return null;
        }

        if (certEncoded.length != repCertEncoded.length) {
            logger.debug("CertificateRepository: Certificate lengths do not match");
            return null;
        }

        for (int i = 0; i < certEncoded.length; i++) {
            if (certEncoded[i] != repCertEncoded[i]) {
                logger.debug("CertificateRepository: Certificate data do not match");
                return null;
            }
        }

        RevocationInfo info = rec.getRevocationInfo();
        logger.debug("CertificateRepository: - revocation date: " + info.getRevocationDate());

        return info;
    }

    public void shutdown() {
    }
}

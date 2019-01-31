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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.replicadb.IReplicaIDRepository;
import com.netscape.certsrv.dbs.repository.IRepository;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;

/**
 * A class represents a generic repository. It maintains unique
 * serial number within repository.
 * <P>
 * To build domain specific repository, subclass should be created.
 * <P>
 *
 * @author galperin
 * @author thomask
 * @version $Revision: 1.4
 *
 *          $, $Date$
 */

public abstract class Repository implements IRepository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Repository.class);

    private BigInteger BI_INCREMENT = null;
    // (the next serialNo to be issued) - 1
    private BigInteger mSerialNo = null;
    // the serialNo attribute stored in db
    private BigInteger mNext = null;

    private String mMaxSerial = null;
    private String mMinSerial = null;
    private String mNextMaxSerial = null;
    private String mNextMinSerial = null;

    protected boolean mEnableRandomSerialNumbers = false;
    protected BigInteger mCounter = null;
    protected BigInteger mMinSerialNo = null;
    protected BigInteger mMaxSerialNo = null;
    private BigInteger mNextMinSerialNo = null;
    private BigInteger mNextMaxSerialNo = null;

    private BigInteger mIncrementNo = null;
    private BigInteger mLowWaterMarkNo = null;

    private IDBSubsystem mDB = null;
    private String mBaseDN = null;
    private boolean mInit = false;
    private int mRadix = 10;
    private int mRepo = -1;

    private BigInteger mLastSerialNo = null;

    /**
     * Constructs a repository.
     * <P>
     */
    public Repository(IDBSubsystem db, int increment, String baseDN)
            throws EDBException {
        mDB = db;
        mBaseDN = baseDN;

        BI_INCREMENT = new BigInteger(Integer.toString(increment));
    }

    /**
     * Resets serial number.
     */
    public void resetSerialNumber(BigInteger serial) throws EBaseException {
        IDBSSession s = mDB.createSession();

        try {
            String name = mBaseDN;
            ModificationSet mods = new ModificationSet();
            mods.add(IRepositoryRecord.ATTR_SERIALNO,
                    Modification.MOD_REPLACE, serial);
            s.modify(name, mods);
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Retrieves the next serial number attr in db.
     * <P>
     *
     * @return next serial number
     */
    protected BigInteger getSerialNumber() throws EBaseException {
        IDBSSession s = mDB.createSession();

        logger.debug("Repository: getSerialNumber()");
        RepositoryRecord rec = null;

        try {
            if (s != null)
                rec = (RepositoryRecord) s.read(mBaseDN);
        } finally {
            if (s != null)
                s.close();
        }

        if (rec == null) {
            logger.error("Repository::getSerialNumber() - "
                     + "- rec is null!");
            throw new EBaseException("rec is null");
        }

        BigInteger serial = rec.getSerialNumber();
        logger.debug("Repository: getSerialNumber  serial=" + serial);

        if (!mInit) {
            // cms may crash after issue a cert but before update
            // the serial number record
            try {
                IDBObj obj = s.read("cn=" +
                        serial + "," + mBaseDN);

                if (obj != null) {
                    serial = serial.add(BigInteger.ONE);
                    setSerialNumber(serial);
                }
            } catch (EBaseException e) {
                // do nothing
            }
            mInit = true;
        }
        return serial;
    }

    /**
     * Updates the serial number to the specified in db.
     * <P>
     *
     * @param num serial number
     */
    protected void setSerialNumber(BigInteger num) throws EBaseException {

        logger.debug("Repository:setSerialNumber " + num.toString());

        return;

    }

    /**
     * Get the maximum serial number.
     *
     * @return maximum serial number
     */
    public String getMaxSerial() {
        return mMaxSerial;
    }

    /**
     * Set the maximum serial number.
     *
     * @param serial maximum number
     * @exception EBaseException failed to set maximum serial number
     */
    public synchronized void setMaxSerial(String serial) throws EBaseException {
        BigInteger maxSerial = null;
        logger.debug("Repository:setMaxSerial " + serial);

        maxSerial = new BigInteger(serial, mRadix);
        if (maxSerial != null) {
            mMaxSerial = serial;
            mMaxSerialNo = maxSerial;
        }
    }

    /**
     * Get the maximum serial number in next range.
     *
     * @return maximum serial number in next range
     */
    public String getNextMaxSerial() {
        return mNextMaxSerial;
    }

    /**
     * Set the maximum serial number in next range
     *
     * @param serial maximum number in next range
     * @exception EBaseException failed to set maximum serial number in next range
     */
    public synchronized void setNextMaxSerial(String serial) throws EBaseException {
        BigInteger maxSerial = null;
        logger.debug("Repository:setNextMaxSerial " + serial);

        maxSerial = new BigInteger(serial, mRadix);
        if (maxSerial != null) {
            mNextMaxSerial = serial;
            mNextMaxSerialNo = maxSerial;
        }

        return;
    }

    /**
     * Get the minimum serial number.
     *
     * @return minimum serial number
     */
    public String getMinSerial() {
        return mMinSerial;
    }

    protected void setLastSerialNo(BigInteger lastSN) {
        mLastSerialNo = lastSN;
    }

    /**
     * init serial number cache
     */
    private void initCache() throws EBaseException {
        mNext = getSerialNumber();
        mRadix = 10;

        logger.debug("Repository: in InitCache");

        if (this instanceof ICertificateRepository) {
            logger.debug("Repository: Instance of Certificate Repository.");
            mRadix = 16;
            mRepo = IDBSubsystem.CERTS;
        } else if (this instanceof IKeyRepository) {
            // Key Repository uses the same configuration parameters as Certificate
            // Repository.  This is ok because they are on separate subsystems.
            logger.debug("Repository: Instance of Key Repository");
            mRadix = 16;
            mRepo = IDBSubsystem.CERTS;
        } else if (this instanceof IReplicaIDRepository) {
            logger.debug("Repository: Instance of Replica ID repository");
            mRepo = IDBSubsystem.REPLICA_ID;
        } else {
            // CRLRepository subclasses this too, but does not use serial number stuff
            logger.debug("Repository: Instance of Request Repository or CRLRepository.");
            mRepo = IDBSubsystem.REQUESTS;
        }

        mMinSerial = mDB.getMinSerialConfig(mRepo);
        mMaxSerial = mDB.getMaxSerialConfig(mRepo);
        mNextMinSerial = mDB.getNextMinSerialConfig(mRepo);
        mNextMaxSerial = mDB.getNextMaxSerialConfig(mRepo);
        String increment = mDB.getIncrementConfig(mRepo);
        String lowWaterMark = mDB.getLowWaterMarkConfig(mRepo);

        logger.debug("Repository: minSerial:" + mMinSerial + " maxSerial: " + mMaxSerial);
        logger.debug("Repository: nextMinSerial: " + ((mNextMinSerial == null)? "" : mNextMinSerial) +
                             " nextMaxSerial: " + ((mNextMaxSerial == null) ? "" : mNextMaxSerial));
        logger.debug("Repository: increment:" + increment + " lowWaterMark: " + lowWaterMark);

        if (mMinSerial != null)
            mMinSerialNo = new BigInteger(mMinSerial, mRadix);

        if (mMaxSerial != null)
            mMaxSerialNo = new BigInteger(mMaxSerial, mRadix);

        if (mNextMinSerial != null)
            mNextMinSerialNo = new BigInteger(mNextMinSerial, mRadix);

        if (mNextMaxSerial != null)
            mNextMaxSerialNo = new BigInteger(mNextMaxSerial, mRadix);

        if (lowWaterMark != null)
            mLowWaterMarkNo = new BigInteger(lowWaterMark, mRadix);

        if (increment != null)
            mIncrementNo = new BigInteger(increment, mRadix);

        BigInteger theSerialNo = null;
        theSerialNo = getLastSerialNumberInRange(mMinSerialNo, mMaxSerialNo);

        if (theSerialNo == null) {
            // This arises when range has been depleted by servicing
            // UpdateNumberRange requests for clones.  Attempt to
            // move to next range.
            logger.debug(
                "Repository: failed to get last serial number in range "
                + mMinSerialNo + ".." + mMaxSerialNo);

            if (hasNextRange()) {
                logger.debug("Repository: switching to next range.");
                switchToNextRange();
                logger.debug("Repository: new range: " + mMinSerialNo + ".." + mMaxSerialNo);
                // try again with updated range
                theSerialNo = getLastSerialNumberInRange(mMinSerialNo, mMaxSerialNo);
            } else {
                logger.debug("Repository: next range not available.");
            }
        }

        if (theSerialNo != null) {

            mLastSerialNo = new BigInteger(theSerialNo.toString());
            logger.debug("Repository:  mLastSerialNo: " + mLastSerialNo);

        } else {

            throw new EBaseException("Error in obtaining the last serial number in the repository!");

        }

    }

    protected void initCacheIfNeeded() throws EBaseException {
        if (mLastSerialNo == null)
            initCache();
    }

    /**
     * Peek at the next serial number in cache (does not consume the
     * number).
     *
     * The returned number is not necessarily the previously emitted
     * serial number plus one, i.e. if we are going to roll into the
     * next range.  This method does not actually switch the range.
     *
     * Returns null if the next number exceeds the current range and
     * there is not a next range.
     */
    public synchronized BigInteger peekNextSerialNumber() throws EBaseException {

        logger.debug("Repository:In getTheSerialNumber ");
        if (mLastSerialNo == null)
            initCache();
        BigInteger serial = mLastSerialNo.add(BigInteger.ONE);

        if (mMaxSerialNo != null && serial.compareTo(mMaxSerialNo) > 0)
            return hasNextRange() ? mNextMinSerialNo : null;
        else
            return serial;
    }

    /**
     * Updates the serial number to the specified in db and cache.
     * <P>
     *
     * @param num serial number
     */
    public void setTheSerialNumber(BigInteger num) throws EBaseException {
        // mSerialNo is already set. But just in case

        logger.debug("Repository:In setTheSerialNumber " + num);
        if (mLastSerialNo == null)
            initCache();

        if (num.compareTo(mSerialNo) <= 0) {
            throw new EDBException(CMS.getUserMessage("CMS_DBS_SETBACK_SERIAL",
                    mSerialNo.toString(16)));
        }
        // write the config parameter. It's needed in case the serialNum gap
        // < BI_INCREMENT and server restart right afterwards.
        mDB.setNextSerialConfig(num);

        mSerialNo = num.subtract(BigInteger.ONE);
        mNext = num.add(BI_INCREMENT);
        setSerialNumber(mNext);
    }

    /**
     * Retrieves the next serial number, and also increase the
     * serial number by one.
     * <P>
     *
     * @return serial number
     */
    public synchronized BigInteger getNextSerialNumber() throws
            EBaseException {

        logger.debug("Repository: in getNextSerialNumber. ");

        if (mLastSerialNo == null) {
            initCache();
        }
        if (mLastSerialNo == null) {
            logger.error("Repository::getNextSerialNumber() " +
                       "- mLastSerialNo is null!");
            throw new EBaseException("mLastSerialNo is null");
        }

        /* Advance the serial number.  checkRange() will check if it exceeds
         * the current range and, if so, rolls to the next range and resets
         * mLastSerialNo to the start of the new range.  Hence we return
         * mLastSerialNo below, after the call to checkRange().
         */
        mLastSerialNo = mLastSerialNo.add(BigInteger.ONE);

        checkRange();

        logger.debug("Repository: getNextSerialNumber: returning " + mLastSerialNo);
        return mLastSerialNo;
    }

    /**
     * Checks if the given number is in the current range.
     * If it does not exceed the current range, return cleanly.
     * If it exceeds the given range, and there is a next range, switch the range.
     * If it exceeds the given range, and there is not a next range, throw EDBException.
     *
     * Precondition: the serial number should already have been advanced.
     * This method will detect that and switch to the next range, including
     * resetting mLastSerialNo to the start of the new (now current) range.
     *
     * Postcondition: the caller should again read mLastSerialNo after
     * calling checkRange(), in case checkRange switched the range and the
     * new range is not adjacent to the current range.
     *
     * @exception EDBException thrown when range switch is needed
     *                           but next range is not allocated
     */
    protected void checkRange() throws EBaseException
    {
        // check if we have reached the end of the range
        // if so, move to next range
        BigInteger randomLimit = null;
        BigInteger rangeLength = null;
        if ((this instanceof ICertificateRepository) &&
            mDB.getEnableSerialMgmt() && mEnableRandomSerialNumbers) {
            rangeLength = mMaxSerialNo.subtract(mMinSerialNo).add(BigInteger.ONE);
            randomLimit = rangeLength.subtract(mLowWaterMarkNo.shiftRight(1));
            logger.debug("Repository: checkRange  rangeLength=" + rangeLength);
            logger.debug("Repository: checkRange  randomLimit=" + randomLimit);
        }
        logger.debug("Repository: checkRange  mLastSerialNo="+mLastSerialNo);
        if (mLastSerialNo.compareTo( mMaxSerialNo ) > 0 ||
            ((!CMS.isPreOpMode()) && randomLimit != null && mCounter.compareTo(randomLimit) > 0)) {

            if (mDB.getEnableSerialMgmt()) {
                logger.debug("Reached the end of the range.  Attempting to move to next range");
                if (!hasNextRange()) {
                    if (rangeLength != null && mCounter.compareTo(rangeLength) < 0) {
                        return;
                    } else {
                        throw new EDBException(CMS.getUserMessage("CMS_DBS_LIMIT_REACHED",
                                                                  mLastSerialNo.toString()));
                    }
                }
                switchToNextRange();
            } else {
                throw new EDBException(CMS.getUserMessage("CMS_DBS_LIMIT_REACHED",
                        mLastSerialNo.toString()));
            }
        }
    }

    /**
     * Return true iff there is a next range ready to go.
     */
    private boolean hasNextRange() {
        return (mNextMinSerialNo != null) && (mNextMaxSerialNo != null);
    }

    /**
     * Switch to the next range and persist the changes.
     */
    private void switchToNextRange()
            throws EBaseException {
        mMinSerialNo = mNextMinSerialNo;
        mMaxSerialNo = mNextMaxSerialNo;
        mLastSerialNo = mMinSerialNo;
        mNextMinSerialNo  = null;
        mNextMaxSerialNo  = null;
        mCounter = BigInteger.ZERO;

        // persist the changes
        mDB.setMinSerialConfig(mRepo, mMinSerialNo.toString(mRadix));
        mDB.setMaxSerialConfig(mRepo, mMaxSerialNo.toString(mRadix));
        mDB.setNextMinSerialConfig(mRepo, null);
        mDB.setNextMaxSerialConfig(mRepo, null);
    }

    /**
     * Checks to see if a new range is needed, or if we have reached the end of the
     * current range, or if a range conflict has occurred.
     *
     * @exception EBaseException failed to check next range for conflicts
     */
    public void checkRanges() throws EBaseException {
        if (!mDB.getEnableSerialMgmt()) {
            logger.warn("Repository: Serial Management not enabled. Returning .. ");
            return;
        }
        if (CMS.getEESSLPort() == null) {
            logger.warn("Repository: Server not completely started.  Returning ..");
            return;
        }

        if (mLastSerialNo == null)
            initCache();

        BigInteger numsInRange = null;
        if ((this instanceof ICertificateRepository) &&
            mDB.getEnableSerialMgmt() && mEnableRandomSerialNumbers) {
            numsInRange = (mMaxSerialNo.subtract(mMinSerialNo)).subtract(mCounter);
        } else {
            numsInRange = mMaxSerialNo.subtract(mLastSerialNo);
        }

        logger.debug("Repository: Serial numbers left in range: " + numsInRange);
        logger.debug("Repository: Last serial number: " + mLastSerialNo);

        BigInteger numsInNextRange = null;
        BigInteger numsAvail = null;

        if ((mNextMaxSerialNo != null) && (mNextMinSerialNo != null)) {
            numsInNextRange = mNextMaxSerialNo.subtract(mNextMinSerialNo).add(BigInteger.ONE);
            numsAvail = numsInRange.add(numsInNextRange);
            logger.debug("Repository: Serial numbers in next range: " + numsInNextRange);
        } else {
            numsAvail = numsInRange;
        }

        logger.debug("Repository: Serial numbers available: " + numsAvail);
        logger.debug("Repository: Low water mark: " + mLowWaterMarkNo);

        if ((numsAvail.compareTo(mLowWaterMarkNo) < 0) && (!CMS.isPreOpMode())) {
            logger.debug("Repository: Requesting next range");
            String nextRange = mDB.getNextRange(mRepo);
            logger.debug("Repository: next range: " + nextRange);

            mNextMinSerialNo = new BigInteger(nextRange, mRadix);
            if (mNextMinSerialNo == null) {
                logger.debug("Repository: Next range not available");
            } else {
                logger.debug("Repository: Next min serial number: " + mNextMinSerialNo.toString(mRadix));
                mNextMaxSerialNo = mNextMinSerialNo.add(mIncrementNo).subtract(BigInteger.ONE);
                numsAvail = numsAvail.add(mIncrementNo);
                mDB.setNextMinSerialConfig(mRepo, mNextMinSerialNo.toString(mRadix));
                mDB.setNextMaxSerialConfig(mRepo, mNextMaxSerialNo.toString(mRadix));
            }
        }

        if (numsInRange.compareTo(mLowWaterMarkNo) < 0) {
            // check for a replication error
            logger.debug("Checking for a range conflict");
            if (mDB.hasRangeConflict(mRepo)) {
                logger.debug("Range Conflict found! Removing next range.");
                mNextMaxSerialNo = null;
                mNextMinSerialNo = null;
                mDB.setNextMinSerialConfig(mRepo, null);
                mDB.setNextMaxSerialConfig(mRepo, null);
            }
        }
    }

    /**
     * Sets whether serial number management is enabled for certs
     * and requests.
     *
     * @param value true/false
     * @exception EBaseException failed to set
     */
    public void setEnableSerialMgmt(boolean value) throws EBaseException {
        mDB.setEnableSerialMgmt(value);
    }

    public abstract BigInteger getLastSerialNumberInRange(BigInteger serial_low_bound, BigInteger serial_upper_bound)
            throws
            EBaseException;
}

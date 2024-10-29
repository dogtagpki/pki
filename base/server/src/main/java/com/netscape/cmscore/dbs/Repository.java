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
import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

/**
 * A class represents a generic repository. It maintains unique
 * serial number within repository.
 *
 * To build domain specific repository, subclass should be created.
 *
 * @author galperin
 * @author thomask
 */

public abstract class Repository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Repository.class);

    public static final int HEX = 16;
    public static final int DEC = 10;

    public enum IDGenerator {
        LEGACY_2("legacy2"),
        LEGACY("legacy"),
        RANDOM("random");

        private String name;

        private IDGenerator(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }

        public static IDGenerator fromString(String name) {
            for (IDGenerator idGenerator : values()) {
                if (idGenerator.name.equals(name)) return idGenerator;
            }
            throw new IllegalArgumentException("Invalid ID generator: " + name);
        }
    }

    protected CMSEngine engine;

    // (the next serialNo to be issued) - 1
    private BigInteger mSerialNo = null;

    protected BigInteger mMinSerialNo;
    protected BigInteger mMaxSerialNo;

    protected BigInteger mNextMinSerialNo;
    protected BigInteger mNextMaxSerialNo;

    protected BigInteger mCounter = null;

    protected BigInteger mIncrementNo;
    protected BigInteger mLowWaterMarkNo;

    protected DBSubsystem dbSubsystem;
    protected String mBaseDN;
    protected String rangeDN;

    protected int mRadix;
    protected Hashtable<String, String> repositoryConfig = new Hashtable<>();

    private BigInteger mLastSerialNo = null;

    protected IDGenerator idGenerator = IDGenerator.LEGACY;
    protected int idLength;

    protected SecureRandom secureRandom;

    /**
     * Constructs a repository.
     * <P>
     */
    public Repository(DBSubsystem dbSubsystem, int radix) {
        this.dbSubsystem = dbSubsystem;
        this.mRadix = radix;
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    public void init() throws Exception {
    }

    /**
     * Get the LDAP base DN for this repository.
     *
     * This value can be used by the request queue to create the
     * name for the request records themselves.
     *
     * @return the LDAP base DN.
     */
    public String getBaseDN() {
        return mBaseDN;
    }

    public int getRadix() {
        return mRadix;
    }

    /**
     * Get the maximum serial number.
     *
     * @return maximum serial number
     */
    public BigInteger getMaxSerial() {
        return mMaxSerialNo;
    }

    /**
     * Set the maximum serial number.
     *
     * @param serial maximum number
     * @exception EBaseException failed to set maximum serial number
     */
    public synchronized void setMaxSerial(BigInteger serial) throws EBaseException {
        logger.debug("Repository: Setting max serial to " + serial);
        mMaxSerialNo = serial;
    }

    /**
     * Get the maximum serial number in next range.
     *
     * @return maximum serial number in next range
     */
    public BigInteger getNextMaxSerial() {
        return mNextMaxSerialNo;
    }

    /**
     * Set the maximum serial number in next range
     *
     * @param serial maximum number in next range
     * @exception EBaseException failed to set maximum serial number in next range
     */
    public synchronized void setNextMaxSerial(BigInteger serial) throws EBaseException {
        logger.debug("Repository: Setting next max serial to " + serial);
        mNextMaxSerialNo = serial;
    }

    /**
     * Get the minimum serial number.
     *
     * @return minimum serial number
     */
    public BigInteger getMinSerial() {
        return mMinSerialNo;
    }

    protected void setLastSerialNo(BigInteger lastSN) {
        mLastSerialNo = lastSN;
    }

    public IDGenerator getIDGenerator() {
        return idGenerator;
    }

    protected void setIDGenerator(IDGenerator idGenerator) {
        this.idGenerator = idGenerator;
    }

    protected void setIDGenerator(String idGenerator) {
        this.idGenerator = IDGenerator.fromString(idGenerator);
    }

    /**
     * init serial number cache
     */
    protected void initCache() throws EBaseException {

        if (idGenerator == IDGenerator.RANDOM) {
            return;
        }

        logger.debug("Repository: in InitCache");

        if (mLastSerialNo != null) {
            return;
        }

        logger.info("Repository: Getting last serial number in range " + mMinSerialNo + ".." + mMaxSerialNo);
        BigInteger theSerialNo = getLastSerialNumberInRange(mMinSerialNo, mMaxSerialNo);

        if (theSerialNo == null) {
            // This arises when range has been depleted by servicing
            // UpdateNumberRange requests for clones.  Attempt to
            // move to next range.
            logger.warn("Repository: Range " + mMinSerialNo + ".." + mMaxSerialNo + " has been depleted");

            if (hasNextRange()) {
                logger.info("Repository: Switching to next range");
                switchToNextRange();

                logger.info("Repository: Getting last serial number in new range " + mMinSerialNo + ".." + mMaxSerialNo);
                theSerialNo = getLastSerialNumberInRange(mMinSerialNo, mMaxSerialNo);

            } else {
                logger.warn("Repository: Next range not available");
            }
        }

        if (theSerialNo != null) {
            mLastSerialNo = new BigInteger(theSerialNo.toString());
            logger.debug("Repository: Last serial number: " + mLastSerialNo);

        } else {
            throw new EBaseException("Error in obtaining the last serial number in the repository!");
        }
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
     *
     * @return serial number
     * @exception EBaseException failed to retrieve next serial number
     */
    public synchronized BigInteger peekNextSerialNumber() throws EBaseException {

        logger.debug("Repository:In getTheSerialNumber ");

        initCache();

        BigInteger serial = mLastSerialNo.add(BigInteger.ONE);

        if (mMaxSerialNo != null && serial.compareTo(mMaxSerialNo) > 0) {
            return hasNextRange() ? mNextMinSerialNo : null;
        }
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

        initCache();

        if (num.compareTo(mSerialNo) <= 0) {
            throw new DBException(CMS.getUserMessage("CMS_DBS_SETBACK_SERIAL",
                    mSerialNo.toString(16)));
        }
        // write the config parameter. It's needed in case the serialNum gap
        // < BI_INCREMENT and server restart right afterwards.
        dbSubsystem.setNextSerialConfig(num);

        mSerialNo = num.subtract(BigInteger.ONE);
    }

    /**
     * Retrieves the next serial number, and also increase the
     * serial number by one.
     *
     * @return serial number
     * @exception EBaseException failed to retrieve next serial number
     */
    public synchronized BigInteger getNextSerialNumber() throws
            EBaseException {

        if (idGenerator == IDGenerator.RANDOM) {

            logger.debug("Repository: Generating random serial number");

            // JSS BigInt does not allow negative value.
            // The following BigInteger constructor will
            // always create a non-negative number.
            BigInteger id = new BigInteger(idLength, secureRandom);
            logger.debug("Repository: - id: 0x" + id.toString(16));

            return id;
        }

        logger.debug("Repository: in getNextSerialNumber. ");

        initCache();

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

    public BigInteger getRangeLength() {
        return null;
    }

    public BigInteger getRandomLimit(BigInteger rangeLength) {
        return null;
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
     * @exception DBException thrown when range switch is needed
     *                           but next range is not allocated
     */
    protected void checkRange() throws EBaseException
    {
        // check if we have reached the end of the range
        // if so, move to next range

        BigInteger rangeLength = getRangeLength();
        logger.debug("Repository: range length: " + rangeLength);

        BigInteger randomLimit = getRandomLimit(rangeLength);
        logger.debug("Repository: random limit: " + randomLimit);

        logger.debug("Repository: checkRange  mLastSerialNo="+mLastSerialNo);
        if (mLastSerialNo.compareTo( mMaxSerialNo ) > 0 ||
            ((!engine.isPreOpMode()) && randomLimit != null && mCounter.compareTo(randomLimit) > 0)) {

            if (dbSubsystem.getEnableSerialMgmt()) {
                logger.debug("Reached the end of the range.  Attempting to move to next range");
                if (!hasNextRange()) {
                    if (rangeLength == null || mCounter.compareTo(rangeLength) >= 0) {
                        throw new DBException(CMS.getUserMessage("CMS_DBS_LIMIT_REACHED",
                                                                  mLastSerialNo.toString()));
                    }
                    return;
                }
                switchToNextRange();
            } else {
                throw new DBException(CMS.getUserMessage("CMS_DBS_LIMIT_REACHED",
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
     * Sets minimum serial number limit in config file
     *
     * @exception EBaseException failed to set
     */

    public abstract void setMinSerialConfig() throws EBaseException;

    /**
     * Sets maximum serial number limit in config file
     *
     * @exception EBaseException failed to set
     */

    public abstract void setMaxSerialConfig() throws EBaseException;

    /**
     * Sets minimum serial number limit for next range in config file
     *
     * @exception EBaseException failed to set
     */

    public abstract void setNextMinSerialConfig() throws EBaseException;

    /**
     * Sets maximum serial number limit for next range in config file
     *
     * @exception EBaseException failed to set
     */
    public abstract void setNextMaxSerialConfig() throws EBaseException;

    /**
     * Switch to the next range and persist the changes.
     */
    private void switchToNextRange() throws EBaseException {

        mMinSerialNo = mNextMinSerialNo;
        mMaxSerialNo = mNextMaxSerialNo;
        mLastSerialNo = mMinSerialNo;
        mNextMinSerialNo  = null;
        mNextMaxSerialNo  = null;
        mCounter = BigInteger.ZERO;

        // persist the changes
        setMinSerialConfig();
        setMaxSerialConfig();
        setNextMinSerialConfig();
        setNextMaxSerialConfig();

        EngineConfig cs = engine.getConfig();
        cs.commit(false);
    }

    public String getNextRangeDN() {
        // store nextRange in repository subtree for SSNv1
        return mBaseDN;
    }

    /**
     * Gets start of next range from database.
     * Increments the nextRange attribute and allocates
     * this range to the current instance by creating a pkiRange object.
     *
     * @return start of next range
     */
    public String getNextRange() throws EBaseException {

        EngineConfig cs = engine.getConfig();

        LDAPSession session = (LDAPSession) dbSubsystem.createSession();

        try {
            LDAPConnection conn = session.getConnection();

            String nextRangeDN = getNextRangeDN();
            logger.info("Repository: Reading next range from " + nextRangeDN);
            LDAPEntry entry = conn.read(nextRangeDN);

            LDAPAttribute attr = entry.getAttribute(DBSubsystem.PROP_NEXT_RANGE);
            if (attr == null) {
                throw new Exception("Missing attribute " + DBSubsystem.PROP_NEXT_RANGE);
            }

            String nextRange = attr.getStringValues().nextElement();

            // parse nextRange as decimal
            BigInteger nextRangeNo = new BigInteger(nextRange);

            BigInteger newNextRangeNo = nextRangeNo.add(mIncrementNo);

            // generate new nextRange in decimal
            String newNextRange = newNextRangeNo.toString();

            // generate endRange in decimal
            String endRange = newNextRangeNo.subtract(BigInteger.ONE).toString();

            logger.info("Repository: Updating next range in " + nextRangeDN);
            logger.info("Repository: - " + DBSubsystem.PROP_NEXT_RANGE + ": " + nextRange + " -> " + newNextRange);

            // To make sure attrNextRange always increments, first delete the current value and then increment.
            // Two operations in the same transaction

            LDAPAttribute attrNextRange = new LDAPAttribute(DBSubsystem.PROP_NEXT_RANGE, newNextRange);
            LDAPModification[] mods = {
                    new LDAPModification(LDAPModification.DELETE, attr),
                    new LDAPModification(LDAPModification.ADD, attrNextRange)
            };

            conn.modify(nextRangeDN, mods);

            // Add new range object

            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectClass", "top"));
            attrs.add(new LDAPAttribute("objectClass", "pkiRange"));

            // store beginRange as decimal
            attrs.add(new LDAPAttribute("beginRange", nextRange));

            // store endRange as decimal
            attrs.add(new LDAPAttribute("endRange", endRange));

            attrs.add(new LDAPAttribute("cn", nextRange));
            attrs.add(new LDAPAttribute("host", cs.getHostname()));
            attrs.add(new LDAPAttribute("securePort", engine.getEESSLPort()));

            String dn2 = "cn=" + nextRange + "," + rangeDN;
            LDAPEntry rangeEntry = new LDAPEntry(dn2, attrs);

            logger.info("Repository: Adding entry " + dn2);
            conn.add(rangeEntry);

            return nextRange;

        } catch (Exception e) {
            logger.warn("Repository: Unable to get next range: " + e.getMessage(), e);
            return null;

        } finally {
            session.close();
        }
    }

    /**
     * Determines if a range conflict has been observed in database.
     * If so, delete the conflicting entries and remove the next range.
     * When the next number is requested, if the number of certs is still
     * below the low water mark, then a new range will be requested.
     *
     * @return true if range conflict, false otherwise
     */
    public boolean hasRangeConflict() throws EBaseException {

        if (mNextMinSerialNo == null) {
            return false;
        }

        EngineConfig cs = engine.getConfig();

        LDAPSession session = (LDAPSession) dbSubsystem.createSession();
        boolean conflict = false;

        try {
            LDAPConnection conn = session.getConnection();

            logger.info("Repository: Searching for conflicting entries");

            String minSerial = idGenerator == IDGenerator.LEGACY_2 ?
                    mMinSerialNo.toString() : mMinSerialNo.toString(mRadix);
            String filter = "(&(nsds5ReplConflict=*)(objectClass=pkiRange)(host= " +
                    cs.getHostname() + ")(SecurePort=" + engine.getEESSLPort() +
                    ")(beginRange=" + minSerial + "))";

            LDAPSearchResults results = conn.search(rangeDN, LDAPv3.SCOPE_SUB, filter, null, false);

            while (results.hasMoreElements()) {
                conflict = true;
                LDAPEntry entry = results.next();
                String dn = entry.getDN();

                logger.info("Repository: Deleting entry " + dn);
                conn.delete(dn);
            }

        } catch (Exception e) {
            logger.warn("Repository: Unable to check next range: " + e.getMessage(), e);

        } finally {
            session.close();
        }

        return conflict;
    }

    public BigInteger getNumbersInRange() {
        return mMaxSerialNo.subtract(mLastSerialNo);
    }

    /**
     * Checks to see if a new range is needed, or if we have reached the end of the
     * current range, or if a range conflict has occurred.
     *
     * @exception EBaseException failed to check next range for conflicts
     */
    public void checkRanges() throws EBaseException {

        if (idGenerator == IDGenerator.RANDOM) {
            return;
        }

        if (!dbSubsystem.getEnableSerialMgmt()) {
            logger.debug("Repository: serial management not enabled, ignore");
            return;
        }

        if (engine.getEESSLPort() == null) {
            logger.warn("Repository: Server not completely started.  Returning ..");
            return;
        }

        initCache();

        BigInteger numsInRange = getNumbersInRange();
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

        if ((numsAvail.compareTo(mLowWaterMarkNo) < 0) && (!engine.isPreOpMode())) {
            logger.debug("Repository: Requesting next range");
            String nextRange = getNextRange();
            logger.debug("Repository: next range: " + nextRange);
            if (idGenerator == IDGenerator.LEGACY_2) {
                mNextMinSerialNo = new BigInteger(nextRange);
            } else {
                // nextRange is read as decimal in other places and with radix (hex default) here making
                // its value inconsistent
                mNextMinSerialNo = new BigInteger(nextRange, mRadix);
            }
            if (mNextMinSerialNo == null) {
                logger.debug("Repository: Next range not available");
            } else {
                logger.debug("Repository: Next min serial number: " + mNextMinSerialNo.toString(mRadix));
                mNextMaxSerialNo = mNextMinSerialNo.add(mIncrementNo).subtract(BigInteger.ONE);
                numsAvail = numsAvail.add(mIncrementNo);

                setNextMinSerialConfig();
                setNextMaxSerialConfig();

                EngineConfig cs = engine.getConfig();
                cs.commit(false);
            }
        }

        if (numsInRange.compareTo(mLowWaterMarkNo) < 0) {
            // check for a replication error
            logger.debug("Checking for a range conflict");
            if (hasRangeConflict()) {
                logger.debug("Range Conflict found! Removing next range.");
                mNextMaxSerialNo = null;
                mNextMinSerialNo = null;

                setNextMinSerialConfig();
                setNextMaxSerialConfig();

                EngineConfig cs = engine.getConfig();
                cs.commit(false);
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
        dbSubsystem.setEnableSerialMgmt(value);
    }

    public abstract BigInteger getLastSerialNumberInRange(BigInteger serial_low_bound, BigInteger serial_upper_bound)
            throws
            EBaseException;
}

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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;

import org.mozilla.jss.netscape.security.x509.X500Name;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBPagedSearch;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.cmscore.apps.DatabaseConfig;

/**
 * A class represents a Key repository. This is the container of
 * archived keys.
 *
 * @author thomask
 */
public class KeyRepository extends Repository {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyRepository.class);

    public static final String PROP_KEY_ID_GENERATOR = "key.id.generator";
    public static final String PROP_KEY_ID_RADIX = "key.id.radix";
    public static final String DEFAULT_KEY_ID_GENERATOR = "legacy";

    public static final String PROP_KEY_ID_LENGTH = "key.id.length";
    public static final int DEFAULT_KEY_ID_LENGTH = 128;

    /**
     * Constructs a key repository. It checks if the key repository
     * does exist. If not, it creates the repository.
     * <P>
     *
     * @param service db service
     * @exception EBaseException failed to setup key repository
     */
    public KeyRepository(
            SecureRandom secureRandom,
            DBSubsystem dbSubsystem) {

        super(dbSubsystem, HEX);
        DatabaseConfig dbc = dbSubsystem.getDBConfigStore();
        try {
            this.mRadix = dbc.getInteger(PROP_KEY_ID_RADIX, HEX);
            logger.debug("KeyRepository: number radix {}", this.mRadix);
            
        } catch (EBaseException ex) {
            logger.debug("KeyRepository: error reading number radix config, using default {} for ", HEX);
        }

        this.secureRandom = secureRandom;
    }

    @Override
    public void init() throws Exception {

        logger.info("KeyRepository: Initializing key repository");

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        mBaseDN = dbConfig.getSerialDN() + "," + dbSubsystem.getBaseDN();
        logger.info("KeyRepository: - base DN: {}", mBaseDN);

        String value = dbConfig.getString(PROP_KEY_ID_GENERATOR, DEFAULT_KEY_ID_GENERATOR);
        logger.info("KeyRepository: - key ID generator: {}", value);
        setIDGenerator(value);

        if (idGenerator == IDGenerator.RANDOM) {

            idLength = dbConfig.getInteger(PROP_KEY_ID_LENGTH, DEFAULT_KEY_ID_LENGTH);
            logger.info("KeyRepository: - key ID length: {}", idLength);
        } else if (idGenerator == IDGenerator.LEGACY_2) {
            initLegacy2Generator();
        } else {
            initLegacyGenerator();
        }

        // register key record schema
        DBRegistry reg = dbSubsystem.getRegistry();
        String[] keyRecordOC = new String[2];

        keyRecordOC[0] = KeyDBSchema.LDAP_OC_TOP;
        keyRecordOC[1] = KeyDBSchema.LDAP_OC_KEYRECORD;

        if (!reg.isObjectClassRegistered(KeyRecord.class.getName())) {
            reg.registerObjectClass(KeyRecord.class.getName(),
                    keyRecordOC);
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_ID)) {
            reg.registerAttribute(KeyRecord.ATTR_ID, new
                    BigIntegerMapper(KeyDBSchema.LDAP_ATTR_SERIALNO));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_ALGORITHM)) {
            reg.registerAttribute(KeyRecord.ATTR_ALGORITHM, new
                    StringMapper(KeyDBSchema.LDAP_ATTR_ALGORITHM));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_STATE)) {
            reg.registerAttribute(KeyRecord.ATTR_STATE, new
                    KeyStateMapper(KeyDBSchema.LDAP_ATTR_STATE));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_KEY_SIZE)) {
            reg.registerAttribute(KeyRecord.ATTR_KEY_SIZE, new
                    IntegerMapper(KeyDBSchema.LDAP_ATTR_KEY_SIZE));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_OWNER_NAME)) {
            reg.registerAttribute(KeyRecord.ATTR_OWNER_NAME, new
                    StringMapper(KeyDBSchema.LDAP_ATTR_OWNER_NAME));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_PRIVATE_KEY_DATA)) {
            reg.registerAttribute(KeyRecord.ATTR_PRIVATE_KEY_DATA, new
                    ByteArrayMapper(KeyDBSchema.LDAP_ATTR_PRIVATE_KEY_DATA));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_PUBLIC_KEY_DATA)) {
            reg.registerAttribute(KeyRecord.ATTR_PUBLIC_KEY_DATA, new
                    PublicKeyMapper(KeyDBSchema.LDAP_ATTR_PUBLIC_KEY_DATA));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_DATE_OF_RECOVERY)) {
            reg.registerAttribute(KeyRecord.ATTR_DATE_OF_RECOVERY, new
                    DateArrayMapper(KeyDBSchema.LDAP_ATTR_DATE_OF_RECOVERY));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_CREATE_TIME)) {
            reg.registerAttribute(KeyRecord.ATTR_CREATE_TIME, new
                    DateMapper(KeyDBSchema.LDAP_ATTR_CREATE_TIME));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_MODIFY_TIME)) {
            reg.registerAttribute(KeyRecord.ATTR_MODIFY_TIME, new
                    DateMapper(KeyDBSchema.LDAP_ATTR_MODIFY_TIME));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_META_INFO)) {
            reg.registerAttribute(KeyRecord.ATTR_META_INFO, new
                    MetaInfoMapper(KeyDBSchema.LDAP_ATTR_META_INFO));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_ARCHIVED_BY)) {
            reg.registerAttribute(KeyRecord.ATTR_ARCHIVED_BY, new
                    StringMapper(KeyDBSchema.LDAP_ATTR_ARCHIVED_BY));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_CLIENT_ID)) {
            reg.registerAttribute(KeyRecord.ATTR_CLIENT_ID, new
                    StringMapper(KeyDBSchema.LDAP_ATTR_CLIENT_ID));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_STATUS)) {
            reg.registerAttribute(KeyRecord.ATTR_STATUS, new
                    StringMapper(KeyDBSchema.LDAP_ATTR_STATUS));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_DATA_TYPE)) {
            reg.registerAttribute(KeyRecord.ATTR_DATA_TYPE, new
                    StringMapper(KeyDBSchema.LDAP_ATTR_DATA_TYPE));
        }
        if (!reg.isAttributeRegistered(KeyRecord.ATTR_REALM)) {
            reg.registerAttribute(KeyRecord.ATTR_REALM, new
                    StringMapper(KeyDBSchema.LDAP_ATTR_REALM));
        }

    }

    protected void initLegacy2Generator() throws EBaseException {
        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        rangeDN = dbConfig.getSerialRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.debug("KeyRepository: - range DN: " + rangeDN);

        mMinSerialNo = dbConfig.getBigInteger(DatabaseConfig.MIN_SERIAL_NUMBER, null);
        logger.debug("KeyRepository: - min serial: " + mMinSerialNo);

        mMaxSerialNo = dbConfig.getBigInteger(DatabaseConfig.MAX_SERIAL_NUMBER, null);
        logger.debug("KeyRepository: - max serial: " + mMaxSerialNo);

        String nextMinSerial = dbConfig.getNextBeginSerialNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = dbConfig.getBigInteger(DatabaseConfig.NEXT_MIN_SERIAL_NUMBER, null);
        }
        logger.debug("KeyRepository: - next min serial: " + mNextMinSerialNo);

        String nextMaxSerial = dbConfig.getNextEndSerialNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = dbConfig.getBigInteger(DatabaseConfig.NEXT_MAX_SERIAL_NUMBER, null);
        }
        logger.debug("KeyRepository: - next max serial: " + mNextMaxSerialNo);

        mLowWaterMarkNo = dbConfig.getBigInteger(DatabaseConfig.SERIAL_LOW_WATER_MARK, null);
        logger.debug("KeyRepository: - low water mark serial: " + mNextMaxSerialNo);

        mIncrementNo = dbConfig.getBigInteger(DatabaseConfig.SERIAL_INCREMENT, null);
        logger.debug("KeyRepository: - increment serial: " + mIncrementNo);
    }

    public void initLegacyGenerator() throws Exception {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        rangeDN = dbConfig.getSerialRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.info("KeyRepository: - range DN: {}", rangeDN);

        String minSerial = dbConfig.getBeginSerialNumber();
        if (minSerial != null) {
            mMinSerialNo = new BigInteger(minSerial, mRadix);
        }
        logger.info("KeyRepository: - min serial: {}", mMinSerialNo);

        String maxSerial = dbConfig.getEndSerialNumber();
        if (maxSerial != null) {
            mMaxSerialNo = new BigInteger(maxSerial, mRadix);
        }
        logger.info("KeyRepository: - max serial: {}", mMaxSerialNo);

        String nextMinSerial = dbConfig.getNextBeginSerialNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = new BigInteger(nextMinSerial, mRadix);
        }
        logger.info("KeyRepository: - next min serial: {}", mNextMinSerialNo);

        String nextMaxSerial = dbConfig.getNextEndSerialNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = new BigInteger(nextMaxSerial, mRadix);
        }
        logger.info("KeyRepository: - next max serial: {}", mNextMaxSerialNo);

        String lowWaterMark = dbConfig.getSerialLowWaterMark();
        if (lowWaterMark != null) {
            mLowWaterMarkNo = new BigInteger(lowWaterMark, mRadix);
        }

        String incrementNo = dbConfig.getSerialIncrement();
        if (incrementNo != null) {
            mIncrementNo = new BigInteger(incrementNo, mRadix);
        }
    }

    public void setMinSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();
        String serial = mMinSerialNo.toString(mRadix);
        if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
           serial = "0x" + serial;
        }
        logger.debug("KeyRepository: Setting min serial number: " + serial);
        dbConfig.setBeginSerialNumber(serial);
    }

    public void setMaxSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();
        String serial = mMaxSerialNo.toString(mRadix);
        if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
           serial = "0x" + serial;
        }
        logger.debug("KeyRepository: Setting max serial number: " + serial);
        dbConfig.setEndSerialNumber(serial);
    }

    public void setNextMinSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        if (mNextMinSerialNo == null) {
            logger.debug("KeyRepository: Removing next min number");
            dbConfig.removeNextBeginSerialNumber();

        } else {
            String serial = mNextMinSerialNo.toString(mRadix);
            if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
               serial = "0x" + serial;
            }
            logger.debug("KeyRepository: Setting next min number: " + serial);
            dbConfig.setNextBeginSerialNumber(serial);
        }
    }

    public void setNextMaxSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        if (mNextMaxSerialNo == null) {
            logger.debug("KeyRepository: Removing next max number");
            dbConfig.removeNextEndSerialNumber();

        } else {
            String serial = mNextMaxSerialNo.toString(mRadix);
            if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
               serial = "0x" + serial;
            }
            logger.debug("KeyRepository: Setting next max number: " + serial);
            dbConfig.setNextEndSerialNumber(serial);
        }
    }

    public DBSubsystem getDBSubsystem() {
        return dbSubsystem;
    }

    /**
     * Retrieves the DN of this repository.
     */
    public String getDN() {
        return mBaseDN;
    }

    /**
     * Removes all objects with this repository.
     */
    public void removeAllObjects() throws EBaseException {
        String filter = "(" + KeyRecord.ATTR_OWNER_NAME + "=*" + ")";
        RecordPagedList<KeyRecord> keyRecords = findPagedKeyRecords(filter, null, null);
        for (KeyRecord rec: keyRecords) {
            deleteKeyRecord(rec.getSerialNumber());
        }
    }

    /**
     * Archives a key to the repository.
     *
     * @param record key record
     * @exception EBaseException failed to archive key
     */
    public void addKeyRecord(KeyRecord kRecord) throws EBaseException {

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn" + "=" +
                    kRecord.getSerialNumber().toString() + "," + getDN();

            if (s != null)
                s.add(name, kRecord);
        }
    }

    /**
     * Recovers an archived key by serial number.
     *
     * @param serialNo serial number
     * @return key record
     * @exception EBaseException failed to recover key
     */
    public KeyRecord readKeyRecord(BigInteger serialNo)
            throws EBaseException {
        if (serialNo == null) {
            throw new EBaseException("Invalid Serial Number.");
        }

        KeyRecord rec = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn" + "=" +
                    serialNo.toString() + "," + getDN();

            if (s != null)
                rec = (KeyRecord) s.read(name);
        }
        if (rec == null) {
            throw new EBaseException("Failed to recover Key for Serial Number " + serialNo);
        }
        return rec;
    }

    /**
     * Recovers an archived key by owner name.
     *
     * @param ownerName owner name
     * @return key record
     * @exception EBaseException failed to recover key
     */
    public KeyRecord readKeyRecord(X500Name ownerName)
            throws EBaseException {

        KeyRecord keyRec = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            if (ownerName != null) {
                String filter = "(" + KeyRecord.ATTR_OWNER_NAME + "=" +
                        ownerName.toString() + ")";
                DBSearchResults res = s.search(getDN(), filter);

                keyRec = (KeyRecord) res.nextElement();
            }
        }
        return keyRec;
    }

    /**
     * Recovers archived key using public key.
     *
     * @param publicKey public key that is corresponding
     *            to the private key
     * @return key record
     * @exception EBaseException failed to read key
     */
    public KeyRecord readKeyRecord(PublicKey publicKey)
            throws EBaseException {
        // XXX - setup binary search attributes
        byte[] data = publicKey.getEncoded();

        if (data == null)
            throw new EBaseException("null data");

        KeyRecord rec = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            String filter = "(" + KeyRecord.ATTR_PUBLIC_KEY_DATA + "=" +
                    escapeBinaryData(data) + ")";
            if (s != null) {
                DBSearchResults res = s.search(getDN(), filter);

                rec = (KeyRecord) res.nextElement();
            }
        }
        return rec;
    }

    /**
     * Recovers archived key using b64 encoded cert
     *
     * @param cert b64 encoded cert
     * @return key record
     * @exception EBaseException failed to recover key
     */
    public KeyRecord readKeyRecord(String cert)
            throws EBaseException {

        KeyRecord rec = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            String filter = "(publicKey=x509cert#\"" + cert + "\")";
            logger.debug("KeyRepository: - filter= {}", filter);

            if (s != null) {
                DBSearchResults res = s.search(getDN(), filter);

                rec = (KeyRecord) res.nextElement();
            }
        }
        return rec;
    }

    /**
     * Modifies key record.
     *
     * @param serialNo key identifier
     * @param mods modification of key records
     * @exception EBaseException failed to modify key record
     */
    public void modifyKeyRecord(BigInteger serialNo, ModificationSet mods)
            throws EBaseException {

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn" + "=" +
                    serialNo.toString() + "," + getDN();

            mods.add(KeyRecord.ATTR_MODIFY_TIME, Modification.MOD_REPLACE,
                    new Date());
            if (s != null)
                s.modify(name, mods);
        }
    }

    /**
     * Deletes a key record.
     *
     * @param serialNo key identifier
     * @exception EBaseException failed to delete key record
     */
    public void deleteKeyRecord(BigInteger serialNo)
            throws EBaseException {

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn" + "=" +
                    serialNo.toString() + "," + getDN();

            if (s != null)
                s.delete(name);
        }
    }

    /**
     * Read RFC-2254
     */
    public static String escapeBinaryData(byte[] data) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < data.length; i++) {
            result.append("\\" + Integer.toHexString(data[i]));
        }
        return result.toString();
    }

    /**
     * Searches for private keys.
     *
     * @param filter LDAP filter for the search
     * @param maxSize maximum number of entries to be returned
     * @return a list of private key records
     * @exception EBaseException failed to search keys
     */
    public Enumeration<KeyRecord> searchKeys(String filter, int maxSize)
            throws EBaseException {

        ArrayList<KeyRecord> a = new ArrayList<>();

        try (DBSSession s = dbSubsystem.createSession()) {
            DBSearchResults sr = s.search(getDN(), filter, maxSize);
            while (sr.hasMoreElements()) {
                a.add((KeyRecord) sr.nextElement());
            }
        }
        return Collections.enumeration(a);
    }

    /**
     * Searches for private keys.
     *
     * @param filter LDAP filter for the search
     * @param maxSize maximum number of entries to be returned
     * @param timeLimit timeout value
     * @return a list of private key records
     * @exception EBaseException failed to search keys
     */
    public Enumeration<KeyRecord> searchKeys(String filter, int maxSize, int timeLimit)
            throws EBaseException {

        ArrayList<KeyRecord> a = new ArrayList<>();

        try (DBSSession s = dbSubsystem.createSession()) {
            DBSearchResults sr = s.search(getDN(), filter, maxSize, timeLimit);
            while (sr.hasMoreElements()) {
                a.add((KeyRecord) sr.nextElement());
            }
        }
        return Collections.enumeration(a);
    }

    /**
     * Finds a list of key records that satisfies
     * the filter.
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param sortKey key to use for sorting the returned elements
     * @return a list of keys
     * @exception EBaseException failed to search
     */
    public RecordPagedList<KeyRecord> findPagedKeyRecords(String filter,
            String[] attrs, String sortKey)
            throws EBaseException {

        logger.debug("CertificateRepository.findPagedKeyRecords()");

        try (DBSSession session = dbSubsystem.createSession()) {
            DBPagedSearch<KeyRecord> page = session.<KeyRecord>createPagedSearch(
                    KeyRecord.class,
                    mBaseDN,
                    filter,
                    attrs,
                    sortKey);

            return new RecordPagedList<>(page);
        }
    }

    /**
     * Searches for a list of key records.
     * Here is a list of supported filter attributes:
     *
     * <pre>
     *   keySerialNumber
     *   keyState
     *   algorithm
     *   keySize
     *   keyOwnerName
     *   privateKey
     *   publicKey
     *   dateOfRecovery
     *   keyCreateTime
     *   keyModifyTime
     *   keyMetaInfo
     * </pre>
     *
     * @param filter search filter
     * @param attrs list of attributes to be returned
     * @param pageSize virtual list page size
     * @return list of key records
     * @exception EBaseException failed to search key records
     * @deprecated As of release 11.6.0, replaced by {@link #findPagedKeyRecords(String, String[], String)}
     */
    @Deprecated(since = "11.6.0", forRemoval = true)
    public KeyRecordList findKeyRecordsInList(String filter,
            String[] attrs, int pageSize) throws EBaseException {
        return findKeyRecordsInList(filter, attrs, KeyRecord.ATTR_ID, pageSize);
    }

    /**
     * Searches for a list of key records.
     *
     * @param filter search filter
     * @param attrs list of attributes to be returned
     * @param sortKey name of attribute that the list should be sorted by
     * @param pageSize virtual list page size
     * @return list of key records
     * @exception EBaseException failed to search key records
     * @deprecated As of release 11.6.0, replaced by {@link #findPagedKeyRecords(String, String[], String)}
     */
    @Deprecated(since = "11.6.0", forRemoval = true)
    public KeyRecordList findKeyRecordsInList(String filter,
            String[] attrs, String sortKey, int pageSize)
            throws EBaseException {

        KeyRecordList list = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            if (s != null) {
                list = new KeyRecordList(
                        s.<KeyRecord>createVirtualList(getDN(), "(&(objectclass=" +
                                KeyRecord.class.getName() + ")" + filter + ")",
                                attrs, sortKey, pageSize));
            }
        }
        return list;
    }
    /**
     * Searches for a list of key records.
     *
     * @param filter search filter
     * @param attrs list of attributes to be returned
     * @param jumpTo jump to index
     * @param sortKey name of attribute that the list should be sorted by
     * @param pageSize virtual list page size
     * @return list of key records
     * @exception EBaseException failed to search key records
     *  @deprecated As of release 11.6.0, replaced by {@link #findPagedKeyRecords(String, String[], String)}
     */
    @Deprecated(since = "11.6.0", forRemoval = true)
    public KeyRecordList findKeyRecordsInList(String filter,
            String[] attrs, String jumpTo, String sortKey, int pageSize)
            throws EBaseException {

        KeyRecordList list = null;

        int len = jumpTo.length();

        String jumpToVal = null;

        if (len > 9) {
            jumpToVal = Integer.toString(len) + jumpTo;
        } else {
            jumpToVal = "0" + Integer.toString(len) + jumpTo;
        }

        try (DBSSession s = dbSubsystem.createSession()) {
            if (s != null) {
                list = new KeyRecordList(
                        s.<KeyRecord>createVirtualList(getDN(), "(&(objectclass=" +
                                KeyRecord.class.getName() + ")" + filter + ")",
                                attrs, jumpToVal, sortKey, pageSize));
            }
        }
        return list;
    }

    @Override
    public BigInteger getLastSerialNumberInRange(BigInteger serial_low_bound, BigInteger serial_upper_bound) throws
            EBaseException {

        logger.debug("KeyRepository:  in getLastSerialNumberInRange: low {} high {}",
                serial_low_bound, serial_upper_bound);

        if (serial_low_bound == null
                || serial_upper_bound == null || serial_low_bound.compareTo(serial_upper_bound) >= 0) {
            return null;
        }

        String ldapfilter = "(" + KeyRecord.ATTR_ID + "<="+serial_upper_bound+")";
        String[] attrs = null;

        RecordPagedList<KeyRecord> keyRecords = findPagedKeyRecords(ldapfilter, attrs, "-serialno");
        Iterator<KeyRecord> iRecs = keyRecords.iterator();

        if (iRecs.hasNext()) {
           KeyRecord firstRec = iRecs.next();
           BigInteger serial = firstRec.getSerialNumber();
           if ((serial.compareTo(serial_low_bound) >= 0) &&
                   (serial.compareTo(serial_upper_bound) <= 0)) {
               logger.debug("KeyRepository: getLastSerialNumberInRange returning: {}", serial);
               return serial;
           }
        }

        BigInteger ret = new BigInteger(serial_low_bound.toString(10));

        ret = ret.add(BigInteger.valueOf(-1));

        logger.debug("KeyRepository: getLastSerialNumberInRange returning: {}", ret);
        return ret;

    }

    public void shutdown() {
    }
}

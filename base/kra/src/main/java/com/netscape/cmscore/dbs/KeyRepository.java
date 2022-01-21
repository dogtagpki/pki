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
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.X500Name;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRecordList;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.cmscore.apps.DatabaseConfig;

/**
 * A class represents a Key repository. This is the container of
 * archived keys.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class KeyRepository extends Repository implements IKeyRepository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyRepository.class);

    /**
     * Constructs a key repository. It checks if the key repository
     * does exist. If not, it creates the repository.
     * <P>
     *
     * @param service db service
     * @exception EBaseException failed to setup key repository
     */
    public KeyRepository(DBSubsystem dbSubsystem) {
        super(dbSubsystem, 16);
    }

    public void init() throws Exception {

        logger.info("KeyRepository: Initializing key repository");

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        mBaseDN = dbConfig.getSerialDN() + "," + dbSubsystem.getBaseDN();
        logger.info("KeyRepository: - base DN: " + mBaseDN);

        rangeDN = dbConfig.getSerialRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.info("KeyRepository: - range DN: " + rangeDN);

        minSerialName = DBSubsystem.PROP_MIN_SERIAL_NUMBER;
        String minSerial = dbConfig.getBeginSerialNumber();
        if (minSerial != null) {
            mMinSerialNo = new BigInteger(minSerial, mRadix);
        }
        logger.info("KeyRepository: - min serial: " + mMinSerialNo);

        maxSerialName = DBSubsystem.PROP_MAX_SERIAL_NUMBER;
        String maxSerial = dbConfig.getEndSerialNumber();
        if (maxSerial != null) {
            mMaxSerialNo = new BigInteger(maxSerial, mRadix);
        }
        logger.info("KeyRepository: - max serial: " + mMaxSerialNo);

        nextMinSerialName = DBSubsystem.PROP_NEXT_MIN_SERIAL_NUMBER;
        String nextMinSerial = dbConfig.getNextBeginSerialNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = new BigInteger(nextMinSerial, mRadix);
        }
        logger.info("KeyRepository: - next min serial: " + mNextMinSerialNo);

        nextMaxSerialName = DBSubsystem.PROP_NEXT_MAX_SERIAL_NUMBER;
        String nextMaxSerial = dbConfig.getNextEndSerialNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = new BigInteger(nextMaxSerial, mRadix);
        }
        logger.info("KeyRepository: - next max serial: " + mNextMaxSerialNo);

        String lowWaterMark = dbConfig.getSerialLowWaterMark();
        if (lowWaterMark != null) {
            mLowWaterMarkNo = new BigInteger(lowWaterMark, mRadix);
        }

        String incrementNo = dbConfig.getSerialIncrement();
        if (incrementNo != null) {
            mIncrementNo = new BigInteger(incrementNo, mRadix);
        }

        // register key record schema
        DBRegistry reg = dbSubsystem.getRegistry();
        String keyRecordOC[] = new String[2];

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
        IKeyRecordList list = findKeyRecordsInList(filter,
                    null, "serialno", 10);
        int size = list.getSize();
        Enumeration<IKeyRecord> e = list.getKeyRecords(0, size - 1);
        while (e.hasMoreElements()) {
            IKeyRecord rec = e.nextElement();
            deleteKeyRecord(rec.getSerialNumber());
        }
    }

    /**
     * Archives a key to the repository.
     * <P>
     *
     * @param record key record
     * @exception EBaseException failed to archive key
     */
    @Override
    public void addKeyRecord(IKeyRecord record) throws EBaseException {

        try (DBSSession s = dbSubsystem.createSession()) {
            String name = "cn" + "=" +
                    ((KeyRecord) record).getSerialNumber().toString() + "," + getDN();

            if (s != null)
                s.add(name, record);
        }
    }

    /**
     * Recovers an archived key by serial number.
     * <P>
     *
     * @param serialNo serial number
     * @return key record
     * @exception EBaseException failed to recover key
     */
    @Override
    public IKeyRecord readKeyRecord(BigInteger serialNo)
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
     * <P>
     *
     * @param ownerName owner name
     * @return key record
     * @exception EBaseException failed to recover key
     */
    @Override
    public IKeyRecord readKeyRecord(X500Name ownerName)
            throws EBaseException {

        KeyRecord keyRec = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            if (ownerName != null) {
                String filter = "(" + KeyRecord.ATTR_OWNER_NAME + "=" +
                        ownerName.toString() + ")";
                IDBSearchResults res = s.search(getDN(), filter);

                keyRec = (KeyRecord) res.nextElement();
            }
        }
        return keyRec;
    }

    /**
     * Recovers archived key using public key.
     */
    @Override
    public IKeyRecord readKeyRecord(PublicKey publicKey)
            throws EBaseException {
        // XXX - setup binary search attributes
        byte data[] = publicKey.getEncoded();

        if (data == null)
            throw new EBaseException("null data");

        KeyRecord rec = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            String filter = "(" + KeyRecord.ATTR_PUBLIC_KEY_DATA + "=" +
                    escapeBinaryData(data) + ")";
            if (s != null) {
                IDBSearchResults res = s.search(getDN(), filter);

                rec = (KeyRecord) res.nextElement();
            }
        }
        return rec;
    }

    /**
     * Recovers archived key using b64 encoded cert
     */
    @Override
    public IKeyRecord readKeyRecord(String cert)
            throws EBaseException {

        KeyRecord rec = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            String filter = "(publicKey=x509cert#\"" + cert + "\")";
            logger.debug("filter= " + filter);

            if (s != null) {
                IDBSearchResults res = s.search(getDN(), filter);

                rec = (KeyRecord) res.nextElement();
            }
        }
        return rec;
    }

    /**
     * Modifies key record.
     */
    @Override
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

    @Override
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
    public static String escapeBinaryData(byte data[]) {
        StringBuffer result = new StringBuffer();

        for (int i = 0; i < data.length; i++) {
            result.append("\\" + Integer.toHexString(data[i]));
        }
        return result.toString();
    }

    @Override
    public Enumeration<IKeyRecord> searchKeys(String filter, int maxSize)
            throws EBaseException {

        Vector<IKeyRecord> v = new Vector<>();

        try (DBSSession s = dbSubsystem.createSession()) {
            IDBSearchResults sr = s.search(getDN(), filter, maxSize);
            while (sr.hasMoreElements()) {
                v.add((IKeyRecord) sr.nextElement());
            }
        }
        return v.elements();
    }

    @Override
    public Enumeration<IKeyRecord> searchKeys(String filter, int maxSize, int timeLimit)
            throws EBaseException {

        Vector<IKeyRecord> v = new Vector<>();

        try (DBSSession s = dbSubsystem.createSession()) {
            IDBSearchResults sr = s.search(getDN(), filter, maxSize, timeLimit);
            while (sr.hasMoreElements()) {
                v.add((IKeyRecord) sr.nextElement());
            }
        }
        return v.elements();
    }

    /**
     * Retrieves key record list.
     */
    @Override
    public IKeyRecordList findKeyRecordsInList(String filter,
            String attrs[], int pageSize) throws EBaseException {
        return findKeyRecordsInList(filter, attrs, IKeyRecord.ATTR_ID,
                pageSize);
    }

    @Override
    public IKeyRecordList findKeyRecordsInList(String filter,
            String attrs[], String sortKey, int pageSize)
            throws EBaseException {

        IKeyRecordList list = null;

        try (DBSSession s = dbSubsystem.createSession()) {
            if (s != null) {
                list = new KeyRecordList(
                        s.<IKeyRecord>createVirtualList(getDN(), "(&(objectclass=" +
                                KeyRecord.class.getName() + ")" + filter + ")",
                                attrs, sortKey, pageSize));
            }
        }
        return list;
    }

    public IKeyRecordList findKeyRecordsInList(String filter,
            String attrs[], String jumpTo, String sortKey, int pageSize)
            throws EBaseException {

        IKeyRecordList list = null;

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
                        s.<IKeyRecord>createVirtualList(getDN(), "(&(objectclass=" +
                                KeyRecord.class.getName() + ")" + filter + ")",
                                attrs, jumpToVal, sortKey, pageSize));
            }
        }
        return list;
    }

    @Override
    public BigInteger getLastSerialNumberInRange(BigInteger serial_low_bound, BigInteger serial_upper_bound) throws
            EBaseException {

        logger.debug("KeyRepository:  in getLastSerialNumberInRange: low "
                + serial_low_bound + " high " + serial_upper_bound);

        if (serial_low_bound == null
                || serial_upper_bound == null || serial_low_bound.compareTo(serial_upper_bound) >= 0) {
            return null;
        }

        String ldapfilter = "(" + "serialno" + "=*" + ")";
        String[] attrs = null;

        KeyRecordList recList =
                (KeyRecordList) findKeyRecordsInList(ldapfilter, attrs, serial_upper_bound.toString(10), "serialno",
                        5 * -1);

        int size = -1;
        if (recList != null) {
            size = recList.getSize();
        }

        logger.debug("KeyRepository: getLastSerialNumberInRange: recList size " + size);

        if (size <= 0) {
            logger.debug("KeyRepository: getLastSerialNumberInRange: index may be empty");

            BigInteger ret = new BigInteger(serial_low_bound.toString(10));

            ret = ret.add(new BigInteger("-1"));

            logger.debug("KeyRepository: getLastSerialNumberInRange returning: " + ret);
            return ret;
        }
        int ltSize = recList.getSizeBeforeJumpTo();

        logger.debug("KeyRepository:getLastSerialNumberInRange: ltSize " + ltSize);

        int i;
        KeyRecord curRec = null;

        for (i = 0; i < 5; i++) {
            curRec = (KeyRecord) recList.getKeyRecord(i);

            if (curRec != null) {

                BigInteger serial = curRec.getSerialNumber();

                logger.debug("KeyRepository:  getLastCertRecordSerialNo:  serialno  " + serial);

                if (((serial.compareTo(serial_low_bound) == 0) || (serial.compareTo(serial_low_bound) == 1)) &&
                        ((serial.compareTo(serial_upper_bound) == 0) || (serial.compareTo(serial_upper_bound) == -1))) {
                    logger.debug("KeyRepository: getLastSerialNumberInRange returning: " + serial);
                    return serial;
                }
            } else {
                logger.debug("KeyRepository:  getLastSerialNumberInRange:found null from getCertRecord");
            }
        }

        BigInteger ret = new BigInteger(serial_low_bound.toString(10));

        ret = ret.add(new BigInteger("-1"));

        logger.debug("KeyRepository: getLastSerialNumberInRange returning: " + ret);
        return ret;

    }

    public void shutdown() {
    }
}

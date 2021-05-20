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
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.RevokedCertificate;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.cmscore.apps.DatabaseConfig;

/**
 * A class represents a CRL repository. It stores all the
 * CRL issuing points.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CRLRepository extends Repository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CRLRepository.class);

    public static final String PROP_INCREMENT = "crldbInc";

    private final String mLdapCRLIssuingPointName = "cn";

    /**
     * Constructs a CRL repository.
     */
    public CRLRepository(DBSubsystem dbSubsystem) throws EBaseException {

        // CRLRepository does not use serial number stuff
        super(dbSubsystem, 10);

        logger.info("CRLRepository: Initializing CRL repository");

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        mBaseDN = "ou=crlIssuingPoints,ou=ca," + dbSubsystem.getBaseDN();
        logger.info("CRLRepository: - base DN: " + mBaseDN);

        rangeDN = dbConfig.getRequestRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.info("CRLRepository: - range DN: " + rangeDN);

        minSerialName = DBSubsystem.PROP_MIN_REQUEST_NUMBER;
        String minSerial = dbConfig.getBeginRequestNumber();
        if (minSerial != null) {
            mMinSerialNo = new BigInteger(minSerial, mRadix);
        }
        logger.info("CRLRepository: - min serial: " + mMinSerialNo);

        maxSerialName = DBSubsystem.PROP_MAX_REQUEST_NUMBER;
        String maxSerial = dbConfig.getEndRequestNumber();
        if (maxSerial != null) {
            mMaxSerialNo = new BigInteger(maxSerial, mRadix);
        }
        logger.info("CRLRepository: - max serial: " + mMaxSerialNo);

        nextMinSerialName = DBSubsystem.PROP_NEXT_MIN_REQUEST_NUMBER;
        String nextMinSerial = dbConfig.getNextBeginRequestNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = new BigInteger(nextMinSerial, mRadix);
        }
        logger.info("CRLRepository: - next min serial: " + mNextMinSerialNo);

        nextMaxSerialName = DBSubsystem.PROP_NEXT_MAX_REQUEST_NUMBER;
        String nextMaxSerial = dbConfig.getNextEndRequestNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = new BigInteger(nextMaxSerial, mRadix);
        }
        logger.info("CRLRepository: - next max serial: " + mNextMaxSerialNo);

        String lowWaterMark = dbConfig.getRequestLowWaterMark();
        if (lowWaterMark != null) {
            mLowWaterMarkNo = new BigInteger(lowWaterMark, mRadix);
        }

        String incrementNo = dbConfig.getRequestIncrement();
        if (incrementNo != null) {
            mIncrementNo = new BigInteger(incrementNo, mRadix);
        }

        /*
        DBRegistry reg = dbService.getRegistry();
        String crlRecordOC[] = new String[1];
        crlRecordOC[0] = Schema.LDAP_OC_CRL_RECORD;
        reg.registerObjectClass(CRLIssuingPointRecord.class.getName(), crlRecordOC);
        reg.registerAttribute(ICRLIssuingPointRecord.ATTR_ID,
                new StringMapper(Schema.LDAP_ATTR_CRL_ID));
        reg.registerAttribute(ICRLIssuingPointRecord.ATTR_CRL_NUMBER,
                new BigIntegerMapper(Schema.LDAP_ATTR_CRL_NUMBER));
        reg.registerAttribute(ICRLIssuingPointRecord.ATTR_CRL_SIZE,
                new LongMapper(Schema.LDAP_ATTR_CRL_SIZE));
        reg.registerAttribute(ICRLIssuingPointRecord.ATTR_THIS_UPDATE,
                new DateMapper(Schema.LDAP_ATTR_THIS_UPDATE));
        reg.registerAttribute(ICRLIssuingPointRecord.ATTR_NEXT_UPDATE,
                new DateMapper(Schema.LDAP_ATTR_NEXT_UPDATE));
        reg.registerAttribute(ICRLIssuingPointRecord.ATTR_CRL,
                new ByteArrayMapper(Schema.LDAP_ATTR_CRL));
        */
    }

    /**
     * Removes all objects with this repository.
     */
    public void removeAllObjects() throws EBaseException {
    }

    /**
     * Adds CRL issuing point record.
     *
     * @param rec issuing point record
     * @exception EBaseException failed to add new issuing point record
     */
    public void addCRLIssuingPointRecord(ICRLIssuingPointRecord rec)
            throws EBaseException {
        DBSSession s = dbSubsystem.createSession();

        try {
            String name = mLdapCRLIssuingPointName + "=" + rec.getId() + "," + mBaseDN;

            s.add(name, rec);
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Retrieves all the issuing points' names.
     *
     * @return A list of issuing points' names.
     * @exception EBaseException failed to retrieve all the issuing points' names.
     */
    public Vector<String> getIssuingPointsNames() throws EBaseException {
        DBSSession s = dbSubsystem.createSession();
        try {
            String[] attrs = { ICRLIssuingPointRecord.ATTR_ID, "objectclass" };
            String filter = "objectclass=" + CRLIssuingPointRecord.class.getName();
            IDBSearchResults res = s.search(mBaseDN, filter, attrs);
            Vector<String> v = new Vector<>();
            while (res.hasMoreElements()) {
                ICRLIssuingPointRecord nextelement =
                        (ICRLIssuingPointRecord) res.nextElement();
                logger.debug("CRLRepository getIssuingPointsNames(): name = "
                        + nextelement.getId());
                v.addElement(nextelement.getId());
            }

            return v;
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Reads issuing point record.
     *
     * @return issuing point record
     * @exception EBaseException failed to read issuing point record
     */
    public ICRLIssuingPointRecord readCRLIssuingPointRecord(String id)
            throws EBaseException {

        DBSSession s = null;
        CRLIssuingPointRecord rec = null;

        try {
            s = dbSubsystem.createSession();

            String name = mLdapCRLIssuingPointName + "=" + id + "," + mBaseDN;
            rec = (CRLIssuingPointRecord) s.read(name);

        } finally {
            if (s != null) s.close();
        }

        return rec;
    }

    /**
     * Deletes issuing point record.
     *
     * @param id issuing point record id
     * @exception EBaseException failed to delete issuing point record
     */
    public void deleteCRLIssuingPointRecord(String id)
            throws EBaseException {
        DBSSession s = null;

        try {
            s = dbSubsystem.createSession();
            String name = mLdapCRLIssuingPointName + "=" + id + "," + mBaseDN;

            if (s != null)
                s.delete(name);
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Modifies issuing point record.
     *
     * @param id issuing point record id
     * @param mods set of modifications
     * @exception EBaseException failed to modify issuing point record
     */
    public void modifyCRLIssuingPointRecord(String id,
            ModificationSet mods) throws EBaseException {
        DBSSession s = dbSubsystem.createSession();

        try {
            String name = mLdapCRLIssuingPointName + "=" + id + "," + mBaseDN;

            if (s != null)
                s.modify(name, mods);
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Updates CRL issuing point record.
     *
     * @param id issuing point record id
     * @param newCRL encoded binary CRL
     * @param thisUpdate time of this update
     * @param nextUpdate time of next update
     * @param crlNumber CRL number
     * @param crlSize CRL size
     * @exception EBaseException failed to update issuing point record
     */
    public void updateCRLIssuingPointRecord(String id, byte[] newCRL,
            Date thisUpdate, Date nextUpdate, BigInteger crlNumber, Long crlSize)
            throws EBaseException {
        ModificationSet mods = new ModificationSet();

        if (newCRL != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_CRL,
                    Modification.MOD_REPLACE, newCRL);
        }
        if (nextUpdate != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_NEXT_UPDATE,
                    Modification.MOD_REPLACE, nextUpdate);
        }
        mods.add(ICRLIssuingPointRecord.ATTR_THIS_UPDATE,
                Modification.MOD_REPLACE, thisUpdate);
        mods.add(ICRLIssuingPointRecord.ATTR_CRL_NUMBER,
                Modification.MOD_REPLACE, crlNumber);
        mods.add(ICRLIssuingPointRecord.ATTR_CRL_SIZE,
                Modification.MOD_REPLACE, crlSize);
        modifyCRLIssuingPointRecord(id, mods);
    }

    /**
     * Updates CRL issuing point record.
     *
     * @param id issuing point record id
     * @param newCRL encoded binary CRL
     * @param thisUpdate time of this update
     * @param nextUpdate time of next update
     * @param crlNumber CRL number
     * @param crlSize CRL size
     * @param revokedCerts list of revoked certificates
     * @param unrevokedCerts list of released from hold certificates
     * @param expiredCerts list of expired certificates
     * @exception EBaseException failed to update issuing point record
     */
    public void updateCRLIssuingPointRecord(
            String id,
            byte[] newCRL,
            Date thisUpdate,
            Date nextUpdate,
            BigInteger crlNumber,
            Long crlSize,
            Hashtable<BigInteger, RevokedCertificate> revokedCerts,
            Hashtable<BigInteger, RevokedCertificate> unrevokedCerts,
            Hashtable<BigInteger, RevokedCertificate> expiredCerts)
            throws EBaseException {

        logger.info("CRLReposiotry: Updating CRL issuing point record");

        ModificationSet mods = new ModificationSet();

        if (newCRL != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_CRL, Modification.MOD_REPLACE, newCRL);
        }

        if (nextUpdate != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_NEXT_UPDATE, Modification.MOD_REPLACE, nextUpdate);
        }

        mods.add(ICRLIssuingPointRecord.ATTR_THIS_UPDATE, Modification.MOD_REPLACE, thisUpdate);
        mods.add(ICRLIssuingPointRecord.ATTR_CRL_NUMBER, Modification.MOD_REPLACE, crlNumber);
        mods.add(ICRLIssuingPointRecord.ATTR_CRL_SIZE, Modification.MOD_REPLACE, crlSize);

        if (revokedCerts != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_REVOKED_CERTS, Modification.MOD_REPLACE, revokedCerts);
        }

        if (unrevokedCerts != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_UNREVOKED_CERTS, Modification.MOD_REPLACE, unrevokedCerts);
        }

        if (expiredCerts != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_EXPIRED_CERTS, Modification.MOD_REPLACE, expiredCerts);
        }

        if (revokedCerts != null || unrevokedCerts != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_FIRST_UNSAVED, Modification.MOD_REPLACE, ICRLIssuingPointRecord.CLEAN_CACHE);
        }

        modifyCRLIssuingPointRecord(id, mods);
    }

    /**
     * Updates CRL issuing point record with recently revoked certificates info.
     *
     * @param id issuing point record id
     * @param revokedCerts list of revoked certificates
     * @param unrevokedCerts list of released from hold certificates
     * @exception EBaseException failed to update issuing point record
     */
    public void updateRevokedCerts(
            String id,
            Hashtable<BigInteger, RevokedCertificate> revokedCerts,
            Hashtable<BigInteger, RevokedCertificate> unrevokedCerts)
            throws EBaseException {

        logger.info("CRLReposiotry: Updating revoked certificates");

        ModificationSet mods = new ModificationSet();
        mods.add(ICRLIssuingPointRecord.ATTR_REVOKED_CERTS, Modification.MOD_REPLACE, revokedCerts);
        mods.add(ICRLIssuingPointRecord.ATTR_UNREVOKED_CERTS, Modification.MOD_REPLACE, unrevokedCerts);
        mods.add(ICRLIssuingPointRecord.ATTR_FIRST_UNSAVED, Modification.MOD_REPLACE, ICRLIssuingPointRecord.CLEAN_CACHE);

        modifyCRLIssuingPointRecord(id, mods);
    }

    /**
     * Updates CRL issuing point record with recently expired certificates info.
     *
     * @param id issuing point record id
     * @param expiredCerts list of expired certificates
     * @exception EBaseException failed to update issuing point record
     */
    public void updateExpiredCerts(String id, Hashtable<BigInteger, RevokedCertificate> expiredCerts)
            throws EBaseException {
        ModificationSet mods = new ModificationSet();

        mods.add(ICRLIssuingPointRecord.ATTR_EXPIRED_CERTS,
                Modification.MOD_REPLACE, expiredCerts);
        modifyCRLIssuingPointRecord(id, mods);
    }

    /**
     * Updates CRL issuing point record with CRL cache info.
     *
     * @param id issuing point record id
     * @param crlSize CRL size
     * @param revokedCerts list of revoked certificates
     * @param unrevokedCerts list of released from hold certificates
     * @param expiredCerts list of expired certificates
     * @exception EBaseException failed to update issuing point record
     */
    public void updateCRLCache(String id, Long crlSize,
            Hashtable<BigInteger, RevokedCertificate> revokedCerts,
            Hashtable<BigInteger, RevokedCertificate> unrevokedCerts,
            Hashtable<BigInteger, RevokedCertificate> expiredCerts)
            throws EBaseException {
        ModificationSet mods = new ModificationSet();

        if (crlSize != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_CRL_SIZE,
                    Modification.MOD_REPLACE, crlSize);
        }
        mods.add(ICRLIssuingPointRecord.ATTR_REVOKED_CERTS,
                Modification.MOD_REPLACE, revokedCerts);
        mods.add(ICRLIssuingPointRecord.ATTR_UNREVOKED_CERTS,
                Modification.MOD_REPLACE, unrevokedCerts);
        mods.add(ICRLIssuingPointRecord.ATTR_EXPIRED_CERTS,
                Modification.MOD_REPLACE, expiredCerts);
        mods.add(ICRLIssuingPointRecord.ATTR_FIRST_UNSAVED,
                Modification.MOD_REPLACE, ICRLIssuingPointRecord.CLEAN_CACHE);
        modifyCRLIssuingPointRecord(id, mods);
    }

    /**
     * Updates CRL issuing point record with delta-CRL.
     *
     * @param id issuing point record id
     * @param deltaCRLNumber delta CRL number
     * @param deltaCRLSize delta CRL size
     * @param nextUpdate time of next update
     * @param deltaCRL delta CRL in binary form
     * @exception EBaseException failed to update issuing point record
     */
    public void updateDeltaCRL(String id, BigInteger deltaCRLNumber,
                               Long deltaCRLSize, Date nextUpdate,
                               byte[] deltaCRL)
            throws EBaseException {
        ModificationSet mods = new ModificationSet();

        if (deltaCRLNumber != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_DELTA_NUMBER,
                    Modification.MOD_REPLACE, deltaCRLNumber);
        }
        if (deltaCRLSize != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_DELTA_SIZE,
                    Modification.MOD_REPLACE, deltaCRLSize);
        }
        if (nextUpdate != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_NEXT_UPDATE,
                    Modification.MOD_REPLACE, nextUpdate);
        }
        if (deltaCRL != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_DELTA_CRL,
                    Modification.MOD_REPLACE, deltaCRL);
        }
        modifyCRLIssuingPointRecord(id, mods);
    }

    /**
     * Updates CRL issuing point record with reference to the first
     * unsaved data.
     *
     * @param id issuing point record id
     * @param firstUnsaved reference to the first unsaved data
     * @exception EBaseException failed to update issuing point record
     */
    public void updateFirstUnsaved(String id, String firstUnsaved)
            throws EBaseException {
        ModificationSet mods = new ModificationSet();

        if (firstUnsaved != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_FIRST_UNSAVED,
                    Modification.MOD_REPLACE, firstUnsaved);
        }
        modifyCRLIssuingPointRecord(id, mods);
    }

    @Override
    public BigInteger getLastSerialNumberInRange(BigInteger serial_low_bound, BigInteger serial_upper_bound)
            throws EBaseException {

        return null;
    }
}

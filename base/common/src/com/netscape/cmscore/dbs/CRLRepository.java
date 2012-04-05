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

import netscape.security.x509.RevokedCertificate;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.crldb.ICRLRepository;

/**
 * A class represents a CRL repository. It stores all the
 * CRL issuing points.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CRLRepository extends Repository implements ICRLRepository {

    private final String mLdapCRLIssuingPointName = "cn";
    private IDBSubsystem mDBService;
    private String mBaseDN;

    /**
     * Constructs a CRL repository.
     */
    public CRLRepository(IDBSubsystem dbService, int increment, String baseDN)
            throws EDBException {
        super(dbService, increment, baseDN);
        mBaseDN = baseDN;
        mDBService = dbService;

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
     * Retrieves backend database handle.
     */
    public IDBSubsystem getDBSubsystem() {
        return mDBService;
    }

    /**
     * Retrieves DN of this repository.
     */
    public String getDN() {
        return mBaseDN;
    }

    /**
     * Removes all objects with this repository.
     */
    public void removeAllObjects() throws EBaseException {
    }

    /**
     * Adds CRL issuing points.
     */
    public void addCRLIssuingPointRecord(ICRLIssuingPointRecord rec)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();

        try {
            String name = mLdapCRLIssuingPointName + "=" +
                    ((CRLIssuingPointRecord) rec).getId().toString() + "," + getDN();

            s.add(name, rec);
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Retrieves all issuing points' names
     */
    public Vector<String> getIssuingPointsNames() throws EBaseException {
        IDBSSession s = mDBService.createSession();
        try {
            String[] attrs = { ICRLIssuingPointRecord.ATTR_ID, "objectclass" };
            String filter = "objectclass=" + CMS.getCRLIssuingPointRecordName();
            IDBSearchResults res = s.search(getDN(), filter, attrs);
            Vector<String> v = new Vector<String>();
            while (res.hasMoreElements()) {
                ICRLIssuingPointRecord nextelement =
                        (ICRLIssuingPointRecord) res.nextElement();
                CMS.debug("CRLRepository getIssuingPointsNames(): name = "
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
     */
    public ICRLIssuingPointRecord readCRLIssuingPointRecord(String id)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        CRLIssuingPointRecord rec = null;

        try {
            String name = mLdapCRLIssuingPointName + "=" + id +
                    "," + getDN();

            if (s != null) {
                rec = (CRLIssuingPointRecord) s.read(name);
            }
        } finally {
            if (s != null)
                s.close();
        }
        return rec;
    }

    /**
     * deletes issuing point record.
     */
    public void deleteCRLIssuingPointRecord(String id)
            throws EBaseException {
        IDBSSession s = null;

        try {
            s = mDBService.createSession();
            String name = mLdapCRLIssuingPointName + "=" + id +
                    "," + getDN();

            if (s != null)
                s.delete(name);
        } finally {
            if (s != null)
                s.close();
        }
    }

    public void modifyCRLIssuingPointRecord(String id,
            ModificationSet mods) throws EBaseException {
        IDBSSession s = mDBService.createSession();

        try {
            String name = mLdapCRLIssuingPointName + "=" + id +
                    "," + getDN();

            if (s != null)
                s.modify(name, mods);
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Updates CRL issuing point record.
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
     */
    public void updateCRLIssuingPointRecord(String id, byte[] newCRL,
            Date thisUpdate, Date nextUpdate, BigInteger crlNumber, Long crlSize,
            Hashtable<BigInteger, RevokedCertificate> revokedCerts,
            Hashtable<BigInteger, RevokedCertificate> unrevokedCerts,
            Hashtable<BigInteger, RevokedCertificate> expiredCerts)
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
        if (revokedCerts != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_REVOKED_CERTS,
                    Modification.MOD_REPLACE, revokedCerts);
        }
        if (unrevokedCerts != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_UNREVOKED_CERTS,
                    Modification.MOD_REPLACE, unrevokedCerts);
        }
        if (expiredCerts != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_EXPIRED_CERTS,
                    Modification.MOD_REPLACE, expiredCerts);
        }
        if (revokedCerts != null || unrevokedCerts != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_FIRST_UNSAVED,
                    Modification.MOD_REPLACE, ICRLIssuingPointRecord.CLEAN_CACHE);
        }
        modifyCRLIssuingPointRecord(id, mods);
    }

    /**
     * Updates CRL issuing point record with recently revoked certificates info.
     */
    public void updateRevokedCerts(String id,
            Hashtable<BigInteger, RevokedCertificate> revokedCerts,
            Hashtable<BigInteger, RevokedCertificate> unrevokedCerts)
            throws EBaseException {
        ModificationSet mods = new ModificationSet();

        mods.add(ICRLIssuingPointRecord.ATTR_REVOKED_CERTS,
                Modification.MOD_REPLACE, revokedCerts);
        mods.add(ICRLIssuingPointRecord.ATTR_UNREVOKED_CERTS,
                Modification.MOD_REPLACE, unrevokedCerts);
        mods.add(ICRLIssuingPointRecord.ATTR_FIRST_UNSAVED,
                Modification.MOD_REPLACE, ICRLIssuingPointRecord.CLEAN_CACHE);
        modifyCRLIssuingPointRecord(id, mods);
    }

    /**
     * Updates CRL issuing point record with recently expired certificates info.
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

    public void updateFirstUnsaved(String id, String firstUnsaved)
            throws EBaseException {
        ModificationSet mods = new ModificationSet();

        if (firstUnsaved != null) {
            mods.add(ICRLIssuingPointRecord.ATTR_FIRST_UNSAVED,
                    Modification.MOD_REPLACE, firstUnsaved);
        }
        modifyCRLIssuingPointRecord(id, mods);
    }

    public BigInteger getLastSerialNumberInRange(BigInteger serial_low_bound, BigInteger serial_upper_bound)
            throws EBaseException {

        return null;
    }
}

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

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchResults;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.dbs.IElementProcessor;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertRecordList;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.certdb.IRevocationInfo;
import com.netscape.certsrv.dbs.repository.IRepository;
import com.netscape.certsrv.logging.ILogger;

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

    public final String CERT_X509ATTRIBUTE = "x509signedcert";

    private IDBSubsystem mDBService;
    private String mBaseDN;
    private String mRequestBaseDN;
    private boolean mConsistencyCheck = false;

    @SuppressWarnings("unused")
    private boolean mSkipIfInconsistent;

    private Hashtable<String, ICRLIssuingPoint> mCRLIssuingPoints = new Hashtable<String, ICRLIssuingPoint>();

    private int mTransitMaxRecords = 1000000;
    private int mTransitRecordPageSize = 200;

    CertStatusUpdateTask certStatusUpdateTask;
    RetrieveModificationsTask retrieveModificationsTask;

    IRepository requestRepository;

    /**
     * Constructs a certificate repository.
     */
    public CertificateRepository(IDBSubsystem dbService, String certRepoBaseDN, int increment, String baseDN)
            throws EDBException {
        super(dbService, increment, baseDN);
        mBaseDN = certRepoBaseDN;
        mDBService = dbService;
    }

    public ICertRecord createCertRecord(BigInteger id, Certificate cert, MetaInfo meta) {
        return new CertRecord(id, cert, meta);
    }

    public BigInteger getLastSerialNumberInRange(BigInteger serial_low_bound, BigInteger serial_upper_bound)
            throws EBaseException {

        CMS.debug("CertificateRepository:  in getLastSerialNumberInRange: low "
                + serial_low_bound + " high " + serial_upper_bound);

        if (serial_low_bound == null
                || serial_upper_bound == null || serial_low_bound.compareTo(serial_upper_bound) >= 0) {
            return null;

        }

        String ldapfilter = "(" + "certstatus" + "=*" + ")";

        String[] attrs = null;

        ICertRecordList recList =
                findCertRecordsInList(ldapfilter, attrs, serial_upper_bound.toString(10), "serialno", 5 * -1);

        int size = recList.getSize();

        CMS.debug("CertificateRepository:getLastSerialNumberInRange: recList size " + size);

        if (size <= 0) {
            CMS.debug("CertificateRepository:getLastSerialNumberInRange: index may be empty");

            BigInteger ret = new BigInteger(serial_low_bound.toString(10));

            ret = ret.add(new BigInteger("-1"));
            CMS.debug("CertificateRepository:getLastCertRecordSerialNo: returning " + ret);
            return ret;
        }
        int ltSize = recList.getSizeBeforeJumpTo();

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

                if (((serial.compareTo(serial_low_bound) == 0) || (serial.compareTo(serial_low_bound) == 1)) &&
                        ((serial.compareTo(serial_upper_bound) == 0) || (serial.compareTo(serial_upper_bound) == -1))) {
                    CMS.debug("getLastSerialNumberInRange returning: " + serial);
                    return serial;
                }
            } else {
                CMS.debug("getLastSerialNumberInRange:found null from getCertRecord");
            }
        }

        BigInteger ret = new BigInteger(serial_low_bound.toString(10));

        ret = ret.add(new BigInteger("-1"));

        CMS.debug("CertificateRepository:getLastCertRecordSerialNo: returning " + ret);
        return ret;

    }

    /**
     * Removes all objects with this repository.
     */
    public void removeCertRecords(BigInteger beginS, BigInteger endS) throws EBaseException {
        String filter = "(" + CertRecord.ATTR_CERT_STATUS + "=*" + ")";
        ICertRecordList list = findCertRecordsInList(filter,
                    null, "serialno", 10);
        int size = list.getSize();
        Enumeration<ICertRecord> e = list.getCertRecords(0, size - 1);
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
     * 0 - disable
     * >0 - enable
     */
    public void setCertStatusUpdateInterval(IRepository requestRepository, int interval,
            boolean listenToCloneModifications) {

        CMS.debug("In setCertStatusUpdateInterval " + interval);
        synchronized (this) {
            this.requestRepository = requestRepository;
        }

        // stop running tasks
        if (certStatusUpdateTask != null) {
            certStatusUpdateTask.stop();
        }
        if (retrieveModificationsTask != null) {
            retrieveModificationsTask.stop();
        }

        if (interval == 0) {
            CMS.debug("In setCertStatusUpdateInterval interval = 0");
            return;
        }

        CMS.debug("In setCertStatusUpdateInterval  listenToCloneModifications=" + listenToCloneModifications);

        if (listenToCloneModifications) {
            CMS.debug("In setCertStatusUpdateInterval listening to modifications");
            try {
                retrieveModificationsTask = new RetrieveModificationsTask(this);
                retrieveModificationsTask.start();
            } catch (EBaseException e) {
                retrieveModificationsTask = null;
                e.printStackTrace();
            }
        }

        CMS.debug("In setCertStatusUpdateInterval scheduling cert status update every " + interval + " seconds.");
        certStatusUpdateTask = new CertStatusUpdateTask(this, interval);
        certStatusUpdateTask.start();
    }

    /**
     * This method blocks when another thread (such as the CRL Update) is running
     */
    public synchronized void updateCertStatus() {

        CMS.debug("In updateCertStatus()");

        try {
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

            CMS.debug("Starting cert checkRanges");
            checkRanges();
            CMS.debug("cert checkRanges done");

            CMS.debug("Starting request checkRanges");
            requestRepository.checkRanges();
            CMS.debug("request checkRanges done");

        } catch (Exception e) {
            CMS.debug("updateCertStatus done: " + e.toString());
        }
    }

    public synchronized void processRevokedCerts(IElementProcessor p, String filter, int pageSize)
            throws EBaseException {

        CMS.debug("Starting processRevokedCerts (entered lock)");
        ICertRecordList list = findCertRecordsInList(filter,
                new String[] { ICertRecord.ATTR_ID, ICertRecord.ATTR_REVO_INFO, "objectclass" },
                "serialno",
                pageSize);

        int totalSize = list.getSize();

        list.processCertRecords(0, totalSize - 1, p);
        CMS.debug("processRevokedCerts done");
    }

    /**
     * Retrieves DN of this repository.
     */
    public String getDN() {
        return mBaseDN;
    }

    public void setRequestDN(String requestDN) {
        mRequestBaseDN = requestDN;
    }

    public String getRequestDN() {
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
     *                the repository
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
                 * System.out.println("XXX servlet should set USER_ID");
                 * throw new EBaseException(BaseResources.UNKNOWN_PRINCIPAL_1,
                 * "null");
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
     *                the repository
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

        Vector<Serializable> cList = new Vector<Serializable>(ltSize);

        CMS.debug("transidValidCertificates: list size: " + size);
        CMS.debug("transitValidCertificates: ltSize " + ltSize);

        CertRecord curRec = null;

        int i;
        ICertRecord obj = null;

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
        Vector<Serializable> cList = new Vector<Serializable>(ltSize);

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
            } else {
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

        Vector<Serializable> cList = new Vector<Serializable>(ltSize);

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

    private void transitCertList(Vector<Serializable> cList, String newCertStatus) throws EBaseException {
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

                Enumeration<ICRLIssuingPoint> eIPs = mCRLIssuingPoints.elements();

                while (eIPs.hasMoreElements()) {
                    ICRLIssuingPoint ip = eIPs.nextElement();

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

    public Enumeration<Object> searchCertificates(String filter, int maxSize)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<Object> e = null;

        CMS.debug("searchCertificates filter " + filter + " maxSize " + maxSize);
        try {
            e = s.search(getDN(), filter, maxSize);
        } finally {
            if (s != null)
                s.close();
        }
        return e;
    }

    public Enumeration<ICertRecord> searchCertificates(String filter, int maxSize, int timeLimit)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Vector<ICertRecord> v = new Vector<ICertRecord>();

        CMS.debug("searchCertificateswith time limit filter " + filter);
        try {
            IDBSearchResults sr = s.search(getDN(), filter, maxSize, timeLimit);
            while (sr.hasMoreElements()) {
                v.add((ICertRecord) sr.nextElement());
            }
        } finally {
            if (s != null)
                s.close();
        }
        return v.elements();
    }

    /**
     * Returns a list of X509CertImp that satisfies the filter.
     *
     * @deprecated replaced by <code>findCertificatesInList</code>
     */
    public Enumeration<Object> findCertRecs(String filter)
            throws EBaseException {
        CMS.debug("findCertRecs " + filter);
        IDBSSession s = mDBService.createSession();
        Enumeration<Object> e = null;
        try {
            e = s.search(getDN(), filter);
        } finally {
            if (s != null)
                s.close();
        }
        return e;
    }

    public Enumeration<Object> findCertRecs(String filter, String[] attrs)
            throws EBaseException {

        CMS.debug("findCertRecs " + filter
                 + "attrs " + Arrays.toString(attrs));
        IDBSSession s = mDBService.createSession();
        Enumeration<Object> e = null;
        try {
            e = s.search(getDN(), filter, attrs);
        } finally {
            if (s != null)
                s.close();
        }
        return e;

    }

    public Enumeration<X509CertImpl> findCertificates(String filter)
            throws EBaseException {
        Enumeration<ICertRecord> e = findCertRecords(filter);
        Vector<X509CertImpl> v = new Vector<X509CertImpl>();

        while (e.hasMoreElements()) {
            ICertRecord rec = e.nextElement();

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
    public Enumeration<ICertRecord> findCertRecords(String filter)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
            IDBVirtualList<ICertRecord> vlist = s.<ICertRecord>createVirtualList(getDN(), filter, attrs,
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

            IDBVirtualList<ICertRecord> vlist = s.createVirtualList(getDN(), filter,
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

            IDBVirtualList<ICertRecord> vlist = s.createVirtualList(getDN(), filter,
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
    public static class RenewableCertificateCollection {
        Vector<Object> mToRenew = null;
        Vector<Object> mToNotify = null;

        public RenewableCertificateCollection() {
        }

        public Vector<Object> getRenewable() {
            return mToRenew;
        }

        public Vector<Object> getNotifiable() {
            return mToNotify;
        }

        public void addCertificate(String renewalFlag, Object o) {
            if (renewalFlag.equals(CertRecord.AUTO_RENEWAL_ENABLED)) {
                if (mToRenew == null)
                    mToRenew = new Vector<Object>();
                mToRenew.addElement(o);
            }
            if (renewalFlag.equals(CertRecord.AUTO_RENEWAL_DISABLED)) {
                if (mToNotify == null)
                    mToNotify = new Vector<Object>();
                mToNotify.addElement(o);
            }
        }
    }

    public Hashtable<String, RenewableCertificateCollection> getRenewableCertificates(String renewalTime)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();

        Hashtable<String, RenewableCertificateCollection> tab = null;

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
            Enumeration<ICertRecord> e = list.getCertRecords(0, size - 1);

            tab = new Hashtable<String, RenewableCertificateCollection>();
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
     * @param subjectDN The distinguished name of the subject.
     * @param validityType The type of certificates to get.
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
            Enumeration<ICertRecord> e = list.getCertRecords(0, size - 1);

            Vector<X509CertImpl> v = new Vector<X509CertImpl>();

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
            Enumeration<ICertRecord> e = null;

            if (filter != null && filter.length() > 0) {
                //e = s.search(getDN(), filter);
                ICertRecordList list = null;

                list = findCertRecordsInList(filter, null, "serialno", 10);
                int size = list.getSize();

                e = list.getCertRecords(0, size - 1);
            }

            Vector<X509CertImpl> v = new Vector<X509CertImpl>();

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
     *
     * @param from The starting point of the serial number range.
     * @param to The ending point of the serial number range.
     */
    public Enumeration<ICertRecord> getValidCertificates(String from, String to)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Vector<ICertRecord> v = new Vector<ICertRecord>();

        try {

            // 'from' determines 'jumpto' value
            // 'to' determines where to stop looking

            String ldapfilter = "(certstatus=VALID)";

            String fromVal = "0";
            try {
                if (from != null) {
                    Integer.parseInt(from);
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

            for (int i = 0;; i++) {
                CertRecord rec = (CertRecord) list.getCertRecord(i);
                CMS.debug("processing record: " + i);
                if (rec == null) {
                    break; // no element returned
                } else {

                    CMS.debug("processing record: " + i + " " + rec.getSerialNumber());
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
        CMS.debug("returning " + v.size() + " elements");
        return v.elements();
    }

    /**
     * Retrives all valid certificates excluding ones already revoked.
     */
    public Enumeration<ICertRecord> getAllValidCertificates()
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
     *
     * @param from The starting point of the serial number range.
     * @param to The ending point of the serial number range.
     */
    public Enumeration<ICertRecord> getValidNotPublishedCertificates(String from, String to)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
    public Enumeration<ICertRecord> getAllValidNotPublishedCertificates()
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
     *
     * @param from The starting point of the serial number range.
     * @param to The ending point of the serial number range.
     */
    public Enumeration<ICertRecord> getExpiredCertificates(String from, String to)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
    public Enumeration<ICertRecord> getAllExpiredCertificates()
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
     *
     * @param from The starting point of the serial number range.
     * @param to The ending point of the serial number range.
     */
    public Enumeration<ICertRecord> getExpiredPublishedCertificates(String from, String to)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
    public Enumeration<ICertRecord> getAllExpiredPublishedCertificates()
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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

        ICertRecordList list = null;
        IDBSSession s = mDBService.createSession();

        try {
            String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_INVALID + ")";

            String[] attrs = null;

            if (mConsistencyCheck == false) {
                attrs = new String[] { "objectclass", CertRecord.ATTR_ID, CertRecord.ATTR_X509CERT };
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

        ICertRecordList list = null;
        IDBSSession s = mDBService.createSession();

        try {
            String ldapfilter = "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_VALID + ")";

            String[] attrs = null;

            if (mConsistencyCheck == false) {
                attrs = new String[] { "objectclass", CertRecord.ATTR_ID, CertRecord.ATTR_X509CERT };
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
                            CertRecord.ATTR_REVO_INFO, CertificateValidity.NOT_AFTER, CertRecord.ATTR_X509CERT };
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
     *
     * @param from The starting point of the serial number range.
     * @param to The ending point of the serial number range.
     */
    public Enumeration<ICertRecord> getRevokedCertificates(String from, String to)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
    public Enumeration<ICertRecord> getAllRevokedCertificates()
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;
        // index is setup for this filter
        String ldapfilter = "(|(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")("
                + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED_EXPIRED + "))";

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
     *
     * @param from The starting point of the serial number range.
     * @param to The ending point of the serial number range.
     */
    public Enumeration<ICertRecord> getRevokedPublishedCertificates(String from, String to)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
    public Enumeration<ICertRecord> getAllRevokedPublishedCertificates()
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;
        // index is setup for this filter
        String ldapfilter = "(&(|(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")("
                + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED_EXPIRED + "))";

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
    public Enumeration<ICertRecord> getRevokedCertificates(Date asOfDate)
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;

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
    public Enumeration<ICertRecord> getAllRevokedNonExpiredCertificates()
            throws EBaseException {
        IDBSSession s = mDBService.createSession();
        Enumeration<ICertRecord> e = null;
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

    LDAPSearchResults searchForModifiedCertificateRecords(IDBSSession session) {
        CMS.debug("searchForModifiedCertificateRecords");
        LDAPSearchResults results = null;

        String filter = "(" + CertRecord.ATTR_CERT_STATUS + "=*)";
        try {
            results = session.persistentSearch(getDN(), filter, null);

        } catch (Exception e) {
            CMS.debug("startSearchForModifiedCertificateRecords  persistentSearch Exception=" + e);
        }

        return results;
    }

    public void getModifications(LDAPEntry entry) {
        if (entry != null) {
            CMS.debug("getModifications  entry DN=" + entry.getDN());

            LDAPAttributeSet entryAttrs = entry.getAttributeSet();
            ICertRecord certRec = null;
            try {
                certRec = (ICertRecord) mDBService.getRegistry().createObject(entryAttrs);
            } catch (Exception e) {
            }
            if (certRec != null) {
                String status = certRec.getStatus();
                CMS.debug("getModifications  serialNumber=" + certRec.getSerialNumber() +
                          "  status=" + status);
                if (status != null && (status.equals(ICertRecord.STATUS_VALID) ||
                        status.equals(ICertRecord.STATUS_REVOKED))) {

                    Enumeration<ICRLIssuingPoint> eIPs = mCRLIssuingPoints.elements();

                    while (eIPs.hasMoreElements()) {
                        ICRLIssuingPoint ip = eIPs.nextElement();

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
     * @param cert certificate to verify.
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
        if (certStatusUpdateTask != null) {
            certStatusUpdateTask.stop();
        }

        if (retrieveModificationsTask != null) {
            retrieveModificationsTask.stop();
        }
    }
}

class CertStatusUpdateTask implements Runnable {

    CertificateRepository repository;
    int interval;

    ScheduledExecutorService executorService;

    public CertStatusUpdateTask(CertificateRepository repository, int interval) {
        this.repository = repository;
        this.interval = interval;
    }

    public void start() {
        // schedule task to run immediately and repeat after specified interval
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            public Thread newThread(Runnable r) {
                return new Thread(r, "CertStatusUpdateTask");
            }
        });
        executorService.scheduleWithFixedDelay(this, 0, interval, TimeUnit.SECONDS);
    }

    public void run() {
        repository.updateCertStatus();
    }

    public void stop() {
        // shutdown executorService without interrupting running task
        if (executorService != null) executorService.shutdown();
    }
}

class RetrieveModificationsTask implements Runnable {

    CertificateRepository repository;

    IDBSSession session;
    LDAPSearchResults results;

    ScheduledExecutorService executorService;

    public RetrieveModificationsTask(CertificateRepository repository) {
        this.repository = repository;
    }

    public void start() throws EBaseException {
        // start persistent search
        try {
            session = repository.getDBSubsystem().createSession();
            results = repository.searchForModifiedCertificateRecords(session);
        } catch (EBaseException e) {
            stop(); // avoid leaks
            throw e;
        }

        // schedule task to run immediately and repeat without delay
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            public Thread newThread(Runnable r) {
                return new Thread(r, "RetrieveModificationsTask");
            }
        });
        executorService.scheduleWithFixedDelay(this, 0, 1, TimeUnit.MICROSECONDS);
    }

    public void run() {
        CMS.debug("Inside run method of RetrieveModificationsThread");

        try {
            // results.hasMoreElements() will block until next element becomes available
            // or return false if the search is abandoned or connection is closed
            if (results.hasMoreElements()) {
                LDAPEntry entry = results.next();
                repository.getModifications(entry);
            }
        } catch (Exception e) {
            CMS.debug("Exception: " + e.toString());
        }
        CMS.debug("Done with run method of RetrieveModificationsThread");
    }

    public void stop() {
        if (executorService != null) executorService.shutdown();

        if (session != null) {
            // closing the session doesn't actually close the connection,
            // so the search needs to be abandoned explicitly
            if (results != null) try { session.abandon(results); } catch (Exception e) { e.printStackTrace(); }

            // close session
            try { session.close(); } catch (Exception e) { e.printStackTrace(); }
        }
    }
}

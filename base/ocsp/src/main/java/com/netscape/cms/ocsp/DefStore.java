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
package com.netscape.cms.ocsp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import org.mozilla.jss.asn1.GeneralizedTime;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.netscape.security.x509.RevokedCertificate;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.DBSSession;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.RepositoryRecord;
import com.netscape.cmsutil.ocsp.CertID;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.GoodInfo;
import com.netscape.cmsutil.ocsp.Request;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.UnknownInfo;

/**
 * This is the default OCSP store that stores revocation information
 * as certificate record (CMS internal data structure).
 *
 * @version $Revision$, $Date$
 */
public class DefStore implements IDefStore, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DefStore.class);

    // refreshInSec is useful in the master-clone situation.
    // clone does not know that the CRL has been updated in
    // the master (by default no refresh)
    private static final String PROP_USE_CACHE = "useCache";

    private static final String PROP_REFRESH_IN_SEC = "refreshInSec";
    private static final int DEF_REFRESH_IN_SEC = 0;

    public static final BigInteger BIG_ZERO = new BigInteger("0");
    public static final Long MINUS_ONE = Long.valueOf(-1);

    private final static String PROP_BY_NAME =
            "byName";
    private final static String PROP_WAIT_ON_CRL_UPDATE =
            "waitOnCRLUpdate";
    private final static String PROP_NOT_FOUND_GOOD = "notFoundAsGood";
    private final static String PROP_INCLUDE_NEXT_UPDATE =
            "includeNextUpdate";

    protected Hashtable<String, Long> mReqCounts = new Hashtable<>();
    protected boolean mNotFoundGood = true;
    protected boolean mUseCache = true;
    protected boolean mByName = true;
    protected boolean mIncludeNextUpdate = false;
    protected Hashtable<String, CRLIPContainer> mCacheCRLIssuingPoints = new Hashtable<>();
    private IConfigStore mConfig = null;
    private String mId = null;
    private DBSubsystem dbSubsystem;
    private int mStateCount = 0;

    /**
     * Constructs the default store.
     */
    public DefStore() {
    }

    @Override
    public boolean isByName() {
        return mByName;
    }

    @Override
    public String[] getExtendedPluginInfo(Locale locale) {
        Vector<String> v = new Vector<>();

        v.addElement(PROP_NOT_FOUND_GOOD
                + ";boolean; " + CMS.getUserMessage(locale, "CMS_OCSP_DEFSTORE_PROP_NOT_FOUND_GOOD"));
        v.addElement(PROP_BY_NAME + ";boolean; " + CMS.getUserMessage(locale, "CMS_OCSP_DEFSTORE_PROP_BY_NAME"));
        v.addElement(PROP_INCLUDE_NEXT_UPDATE
                + ";boolean; " + CMS.getUserMessage(locale, "CMS_OCSP_DEFSTORE_PROP_INCLUDE_NEXT_UPDATE"));
        v.addElement(IExtendedPluginInfo.HELP_TEXT + "; " + CMS.getUserMessage(locale, "CMS_OCSP_DEFSTORE_DESC"));
        v.addElement(IExtendedPluginInfo.HELP_TOKEN + ";configuration-ocspstores-defstore");
        return org.mozilla.jss.netscape.security.util.Utils.getStringArrayFromVector(v);
    }

    @Override
    public void init(IConfigStore config, DBSubsystem dbSubsystem) throws EBaseException {

        mConfig = config;
        this.dbSubsystem = dbSubsystem;

        // Standalone OCSP server only stores information about revoked
        // certificates. So there is no way for the OCSP server to
        // tell if a certificate is good (issued) or not.
        // When an OCSP client asks the status of a certificate,
        // the OCSP server by default returns GOOD. If the server
        // returns UNKNOWN, the OCSP client (browser) will display
        // a error dialog that confuses the end-user.
        //
        // OCSP response can return unknown or good when a certificate
        // is not revoked.
        mNotFoundGood = mConfig.getBoolean(PROP_NOT_FOUND_GOOD, true);

        mUseCache = mConfig.getBoolean(PROP_USE_CACHE, true);

        mByName = mConfig.getBoolean(PROP_BY_NAME, true);

        // To include next update in the OCSP response. If included,
        // PSM (client) will check to see if the revoked information
        // is too old or not
        mIncludeNextUpdate = mConfig.getBoolean(PROP_INCLUDE_NEXT_UPDATE,
                    false);

        // init web gateway.
        initWebGateway();

        /**
         * DeleteOldCRLsThread t = new DeleteOldCRLsThread(this);
         * t.start();
         **/
        // deleteOldCRLs();
    }

    /**
     * init web gateway - just gets the ee gateway for this CA.
     */
    private void initWebGateway()
            throws EBaseException {
    }

    @Override
    public IRepositoryRecord createRepositoryRecord() {
        return new RepositoryRecord();
    }

    /**
     * Returns to the client once the CRL is received.
     */
    @Override
    public boolean waitOnCRLUpdate() {
        boolean defaultVal = true;

        try {
            return mConfig.getBoolean(PROP_WAIT_ON_CRL_UPDATE, defaultVal);
        } catch (EBaseException e) {
            return defaultVal;
        }
    }

    public boolean includeNextUpdate() {
        return mIncludeNextUpdate;
    }

    @Override
    public boolean isNotFoundGood() {
        return mNotFoundGood;
    }

    @Override
    public long getReqCount(String id) {
        Long c = mReqCounts.get(id);

        if (c == null)
            return 0;
        else
            return c.longValue();
    }

    public void incReqCount(String id) {
        mReqCounts.put(id, Long.valueOf(getReqCount(id) + 1));
    }

    /**
     * This store will not delete the old CRL until the
     * new one is totally committed.
     */
    public void deleteOldCRLs() throws EBaseException {
        Enumeration<ICRLIssuingPointRecord> recs = searchCRLIssuingPointRecord(
                "objectclass=" + CRLIssuingPointRecord.class.getName(),
                100);
        while (recs.hasMoreElements()) {
            ICRLIssuingPointRecord rec = recs.nextElement();
            deleteOldCRLsInCA(rec.getId());
        }
    }

    public void deleteOldCRLsInCA(String caName) throws EBaseException {
        deleteCRLsInCA (caName, true);
    }

    public void deleteAllCRLsInCA(String caName) throws EBaseException {
        deleteCRLsInCA (caName, false);
    }

    public void deleteCRLsInCA(String caName, boolean oldCRLs) throws EBaseException {
        DBSSession s = dbSubsystem.createSession();

        try {
            ICRLIssuingPointRecord cp = readCRLIssuingPoint(caName);

            if (cp == null)
                return; // nothing to do
            if (cp.getThisUpdate() == null)
                return; // nothing to do
            String thisUpdate = Long.toString(
                    cp.getThisUpdate().getTime());
            String filter = (oldCRLs)? "(!" + IRepositoryRecord.ATTR_SERIALNO + "=" + thisUpdate + ")": "ou=*";
            Enumeration<IRepositoryRecord> e = searchRepository( caName, filter);

            while (e != null && e.hasMoreElements()) {
                IRepositoryRecord r = e.nextElement();
                Enumeration<CertRecord> recs =
                        searchCertRecord(caName,
                                r.getSerialNumber().toString(),
                                CertRecord.ATTR_ID + "=*");

                logger.info("remove CRL 0x" +
                        r.getSerialNumber().toString(16) +
                        " of " + caName);
                String rep_dn = "ou=" +
                        r.getSerialNumber().toString() +
                        ",cn=" + transformDN(caName) + "," +
                        getBaseDN();

                while (recs != null && recs.hasMoreElements()) {
                    CertRecord rec = recs.nextElement();
                    String cert_dn = "cn=" +
                            rec.getSerialNumber().toString() + "," + rep_dn;

                    s.delete(cert_dn);
                }
                s.delete(rep_dn);
            }
        } finally {
            if (s != null)
                s.close();
        }
    }

    @Override
    public void startup() throws EBaseException {
        int refresh = mConfig.getInteger(PROP_REFRESH_IN_SEC,
                DEF_REFRESH_IN_SEC);
        if (refresh > 0) {
            DefStoreCRLUpdater updater =
                    new DefStoreCRLUpdater(mCacheCRLIssuingPoints, refresh);
            updater.start();
        }
    }

    @Override
    public void shutdown() {
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public void setId(String id) throws EBaseException {
        mId = id;
    }

    public String getId() {
        return mId;
    }

    /**
     * Check against the database for status.
     */
    @Override
    public SingleResponse processRequest(Request req) throws Exception {
        // need to find the right CA

        CertID cid = req.getCertID();
        INTEGER serialNo = cid.getSerialNumber();
        logger.debug("DefStore: processing request for cert 0x" + serialNo.toString(16));

        // cache result to speed up the performance
        X509CertImpl theCert = null;
        X509CRLImpl theCRL = null;
        ICRLIssuingPointRecord theRec = null;
        byte keyhsh[] = cid.getIssuerKeyHash().toByteArray();
        CRLIPContainer matched = mCacheCRLIssuingPoints.get(new String(keyhsh));

        if (matched == null) {
            Enumeration<ICRLIssuingPointRecord> recs = searchCRLIssuingPointRecord(
                    "objectclass=" + CRLIssuingPointRecord.class.getName(),
                    100);

            while (recs.hasMoreElements()) {
                ICRLIssuingPointRecord rec = recs.nextElement();
                byte certdata[] = rec.getCACert();
                X509CertImpl cert = null;

                try {
                    cert = new X509CertImpl(certdata);
                } catch (Exception e) {
                    logger.error(CMS.getLogMessage("OCSP_DECODE_CERT", e.toString()), e);
                    throw e;
                }

                MessageDigest md = MessageDigest.getInstance(cid.getDigestName());
                X509Key key = (X509Key) cert.getPublicKey();
                byte digest[] = md.digest(key.getKey());

                if (!Arrays.equals(digest, keyhsh)) {
                    continue;
                }

                theCert = cert;
                theRec = rec;
                incReqCount(theRec.getId());

                byte crldata[] = rec.getCRL();

                if (crldata == null) {
                    throw new Exception("Missing CRL data");
                }

                if (rec.getCRLCache() == null) {
                    logger.debug("DefStore: start building x509 crl impl");
                    try {
                        theCRL = new X509CRLImpl(crldata);
                    } catch (Exception e) {
                        logger.error(CMS.getLogMessage("OCSP_DECODE_CRL", e.toString()), e);
                        throw e;
                    }
                    logger.debug("DefStore: done building x509 crl impl");
                } else {
                    logger.debug("DefStore: using crl cache");
                }

                mCacheCRLIssuingPoints.put(new String(digest), new CRLIPContainer(theRec, theCert, theCRL));
                break;
            }

        } else {
            theCert = matched.getX509CertImpl();
            theRec = matched.getCRLIssuingPointRecord();
            theCRL = matched.getX509CRLImpl();
            incReqCount(theRec.getId());
        }

        if (theCert == null) {
            throw new Exception("Missing issuer certificate");
        }

        // check the serial number
        logger.info("Checked Status of certificate 0x" + serialNo.toString(16));

        GeneralizedTime thisUpdate;

        if (theRec == null) {
            thisUpdate = new GeneralizedTime(new Date());
        } else {
            Date d = theRec.getThisUpdate();
            logger.debug("DefStore: CRL record this update: " + d);
            thisUpdate = new GeneralizedTime(d);
        }

        logger.debug("DefStore: this update: " + thisUpdate.toDate());

        // this is an optional field
        GeneralizedTime nextUpdate;

        if (!includeNextUpdate()) {
            nextUpdate = null;

        } else if (theRec == null) {
            nextUpdate = new GeneralizedTime(new Date());

        } else {
            Date d = theRec.getNextUpdate();
            logger.debug("DefStore: CRL record next update: " + d);
            nextUpdate = new GeneralizedTime(d);
        }

        logger.debug("DefStore: next update: " + (nextUpdate == null ? null : nextUpdate.toDate()));

        CertStatus certStatus;

        if (theCRL == null) {

            certStatus = new UnknownInfo();

            if (theRec == null) {
                return new SingleResponse(cid, certStatus, thisUpdate, nextUpdate);
            }

            // if crl is not available, we can try crl cache
            logger.debug("DefStore: evaluating crl cache");
            Hashtable<BigInteger, RevokedCertificate> cache = theRec.getCRLCacheNoClone();
            if (cache != null) {
                RevokedCertificate rc = cache.get(new BigInteger(serialNo.toString()));
                if (rc == null) {
                    if (isNotFoundGood()) {
                        certStatus = new GoodInfo();
                    } else {
                        certStatus = new UnknownInfo();
                    }
                } else {

                    certStatus = new RevokedInfo(
                            new GeneralizedTime(
                                    rc.getRevocationDate()));
                }
            }

            return new SingleResponse(cid, certStatus, thisUpdate,
                    nextUpdate);
        }

        logger.debug("DefStore: evaluating x509 crl impl");
        X509CRLEntry crlentry = theCRL.getRevokedCertificate(new BigInteger(serialNo.toString()));

        if (crlentry == null) {
            // good or unknown
            if (isNotFoundGood()) {
                certStatus = new GoodInfo();
            } else {
                certStatus = new UnknownInfo();
            }

        } else {
            certStatus = new RevokedInfo(new GeneralizedTime(
                            crlentry.getRevocationDate()));
        }

        return new SingleResponse(cid, certStatus, thisUpdate,
                nextUpdate);
    }

    private String transformDN(String dn) {
        String newdn = dn;

        newdn = newdn.replace(',', '_');
        newdn = newdn.replace('=', '-');
        return newdn;
    }

    public String getBaseDN() {
        return dbSubsystem.getBaseDN();
    }

    @Override
    public Enumeration<ICRLIssuingPointRecord> searchAllCRLIssuingPointRecord(int maxSize)
            throws EBaseException {
        return searchCRLIssuingPointRecord(
                "objectclass=" + CRLIssuingPointRecord.class.getName(),
                maxSize);
    }

    @Override
    public Enumeration<ICRLIssuingPointRecord> searchCRLIssuingPointRecord(String filter,
            int maxSize)
            throws EBaseException {
        DBSSession s = dbSubsystem.createSession();
        Vector<ICRLIssuingPointRecord> v = new Vector<>();

        try {
            IDBSearchResults sr = s.search(getBaseDN(), filter, maxSize);
            while (sr.hasMoreElements()) {
                v.add((ICRLIssuingPointRecord) sr.nextElement());
            }
        } finally {
            if (s != null)
                s.close();
        }
        return v.elements();
    }

    public synchronized void modifyCRLIssuingPointRecord(String name,
            ModificationSet mods) throws EBaseException {
        DBSSession s = dbSubsystem.createSession();

        try {
            String dn = "cn=" +
                    transformDN(name) + "," + getBaseDN();

            s.modify(dn, mods);
        } catch (EBaseException e) {
            logger.error("modifyCRLIssuingPointRecord: " + e.getMessage(), e);
            throw e;
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Returns an issuing point.
     */
    @Override
    public ICRLIssuingPointRecord readCRLIssuingPoint(String name)
            throws EBaseException {
        DBSSession s = dbSubsystem.createSession();
        ICRLIssuingPointRecord rec = null;

        try {
            String dn = "cn=" +
                    transformDN(name) + "," + getBaseDN();

            if (s != null) {
                rec = (ICRLIssuingPointRecord) s.read(dn);
            }
        } finally {
            if (s != null)
                s.close();
        }
        return rec;
    }

    @Override
    public ICRLIssuingPointRecord createCRLIssuingPointRecord(
            String name, BigInteger crlNumber,
            Long crlSize, Date thisUpdate, Date nextUpdate) {
        return new CRLIssuingPointRecord(
                name, crlNumber, crlSize, thisUpdate, nextUpdate);
    }

    @Override
    public void deleteCRLIssuingPointRecord(String id)
            throws EBaseException {

        DBSSession s = null;

        try {
            s = dbSubsystem.createSession();
            String name = "cn=" + transformDN(id) + "," + getBaseDN();
            logger.debug("DefStore::deleteCRLIssuingPointRecord: Attempting to delete: " + name);
            if (s != null) {
                deleteAllCRLsInCA(id);
                s.delete(name);
            }
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Creates a new issuing point in OCSP.
     */
    @Override
    public void addCRLIssuingPoint(String name, ICRLIssuingPointRecord rec)
            throws EBaseException {
        DBSSession s = dbSubsystem.createSession();

        try {
            String dn = "cn=" +
                    transformDN(name) + "," + getBaseDN();

            s.add(dn, rec);
        } finally {
            if (s != null)
                s.close();
        }
    }

    public Enumeration<IRepositoryRecord> searchRepository(String name, String filter)
            throws EBaseException {
        DBSSession s = dbSubsystem.createSession();
        Vector<IRepositoryRecord> v = new Vector<>();

        try {
            IDBSearchResults sr = s.search("cn=" + transformDN(name) + "," + getBaseDN(),
                        filter);
            while (sr.hasMoreElements()) {
                v.add((IRepositoryRecord) sr.nextElement());
            }
        } finally {
            if (s != null)
                s.close();
        }
        return v.elements();
    }

    /**
     * Creates a new issuing point in OCSP.
     */
    @Override
    public void addRepository(String name, String thisUpdate,
            IRepositoryRecord rec)
            throws EBaseException {
        DBSSession s = dbSubsystem.createSession();

        try {
            String dn = "ou=" + thisUpdate + ",cn=" +
                    transformDN(name) + "," + getBaseDN();

            s.add(dn, rec);
        } finally {
            if (s != null)
                s.close();
        }
    }

    public void modifyCertRecord(String name, String thisUpdate,
            String sno,
            ModificationSet mods) throws EBaseException {
        DBSSession s = dbSubsystem.createSession();

        try {
            String dn = "cn=" + sno + ",ou=" + thisUpdate +
                    ",cn=" + transformDN(name) + "," + getBaseDN();

            if (s != null)
                s.modify(dn, mods);
        } finally {
            if (s != null)
                s.close();
        }
    }

    public Enumeration<CertRecord> searchCertRecord(String name, String thisUpdate,
            String filter) throws EBaseException {
        DBSSession s = dbSubsystem.createSession();
        Vector<CertRecord> v = new Vector<>();

        try {
            IDBSearchResults sr = s.search("ou=" + thisUpdate + ",cn=" +
                        transformDN(name) + "," + getBaseDN(),
                        filter);
            while (sr.hasMoreElements()) {
                v.add((CertRecord) sr.nextElement());
            }
        } finally {
            if (s != null)
                s.close();
        }
        return v.elements();
    }

    public CertRecord readCertRecord(String name, String thisUpdate,
            String sno)
            throws EBaseException {
        DBSSession s = dbSubsystem.createSession();
        CertRecord rec = null;

        try {
            String dn = "cn=" + sno + ",ou=" + thisUpdate +
                    ",cn=" + transformDN(name) + "," + getBaseDN();

            if (s != null) {
                rec = (CertRecord) s.read(dn);
            }
        } finally {
            if (s != null)
                s.close();
        }
        return rec;
    }

    /**
     * Creates a new issuing point in OCSP.
     */
    public void addCertRecord(String name, String thisUpdate,
            String sno, CertRecord rec)
            throws EBaseException {
        DBSSession s = dbSubsystem.createSession();

        try {
            String dn = "cn=" + sno + ",ou=" + thisUpdate +
                    ",cn=" + transformDN(name) + "," + getBaseDN();

            s.add(dn, rec);
        } finally {
            if (s != null)
                s.close();
        }
    }

    @Override
    public NameValuePairs getConfigParameters() {
        try {
            NameValuePairs params = new NameValuePairs();

            params.put(Constants.PR_OCSPSTORE_IMPL_NAME,
                    mConfig.getString("class"));
            params.put(PROP_NOT_FOUND_GOOD,
                    mConfig.getString(PROP_NOT_FOUND_GOOD, "true"));
            params.put(PROP_BY_NAME,
                    mConfig.getString(PROP_BY_NAME, "true"));
            params.put(PROP_INCLUDE_NEXT_UPDATE,
                    mConfig.getString(PROP_INCLUDE_NEXT_UPDATE, "false"));
            return params;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void setConfigParameters(NameValuePairs pairs)
            throws EBaseException {

        for (String key : pairs.keySet()) {
            mConfig.put(key, pairs.get(key));
        }
    }

    @Override
    public void updateCRL(X509CRL crl) throws EBaseException {
        try {
            mStateCount++;

            logger.debug("DefStore: Ready to update Issuer");

            try {
                if (!((X509CRLImpl) crl).areEntriesIncluded())
                    crl = new X509CRLImpl(((X509CRLImpl) crl).getEncoded());
            } catch (Exception e) {
                logger.warn("DefStore: " + e.getMessage(), e);
            }

            // commit update
            ModificationSet mods = new ModificationSet();

            if (crl.getThisUpdate() != null)
                mods.add(ICRLIssuingPointRecord.ATTR_THIS_UPDATE,
                        Modification.MOD_REPLACE, crl.getThisUpdate());
            if (crl.getNextUpdate() != null)
                mods.add(ICRLIssuingPointRecord.ATTR_NEXT_UPDATE,
                        Modification.MOD_REPLACE, crl.getNextUpdate());
            if (mUseCache) {
                if (((X509CRLImpl) crl).getListOfRevokedCertificates() != null) {
                    mods.add(ICRLIssuingPointRecord.ATTR_CRL_CACHE,
                            Modification.MOD_REPLACE,
                            ((X509CRLImpl) crl).getListOfRevokedCertificates());
                }
            }
            if (((X509CRLImpl) crl).getNumberOfRevokedCertificates() < 0) {
                mods.add(ICRLIssuingPointRecord.ATTR_CRL_SIZE,
                        Modification.MOD_REPLACE, Long.valueOf(0));
            } else {
                mods.add(ICRLIssuingPointRecord.ATTR_CRL_SIZE,
                        Modification.MOD_REPLACE, Long.valueOf(((X509CRLImpl) crl).getNumberOfRevokedCertificates()));
            }
            BigInteger crlNumber = ((X509CRLImpl) crl).getCRLNumber();
            if (crlNumber == null) {
                mods.add(ICRLIssuingPointRecord.ATTR_CRL_NUMBER,
                        Modification.MOD_REPLACE, new BigInteger("-1"));
            } else {
                mods.add(ICRLIssuingPointRecord.ATTR_CRL_NUMBER,
                        Modification.MOD_REPLACE, crlNumber);
            }
            try {
                mods.add(ICRLIssuingPointRecord.ATTR_CRL,
                        Modification.MOD_REPLACE, crl.getEncoded());
            } catch (Exception e) {
                // ignore
            }
            logger.debug("DefStore: ready to CRL update " +
                    crl.getIssuerDN().getName());
            modifyCRLIssuingPointRecord(
                    crl.getIssuerDN().getName(), mods);
            logger.debug("DefStore: done CRL update " +
                    crl.getIssuerDN().getName());

            // update cache
            mCacheCRLIssuingPoints.clear();

            logger.info("DefStore: Finish Committing CRL." +
                    " thisUpdate=" + crl.getThisUpdate() +
                    " nextUpdate=" + crl.getNextUpdate());

        } finally {
            mStateCount--;
        }
    }

    @Override
    public int getStateCount() {
        return mStateCount;
    }

}

class DeleteOldCRLsThread extends Thread {
    private DefStore mDefStore = null;

    public DeleteOldCRLsThread(DefStore defStore) {
        mDefStore = defStore;
    }

    @Override
    public void run() {
        try {
            mDefStore.deleteOldCRLs();
        } catch (EBaseException e) {
        }
    }
}

class CRLIPContainer {
    private ICRLIssuingPointRecord mRec = null;
    private X509CertImpl mCert = null;
    private X509CRLImpl mCRL = null;

    public CRLIPContainer(ICRLIssuingPointRecord rec, X509CertImpl cert, X509CRLImpl crl) {
        mRec = rec;
        mCert = cert;
        mCRL = crl;
    }

    public ICRLIssuingPointRecord getCRLIssuingPointRecord() {
        return mRec;
    }

    public X509CertImpl getX509CertImpl() {
        return mCert;
    }

    public X509CRLImpl getX509CRLImpl() {
        return mCRL;
    }
}

class DefStoreCRLUpdater extends Thread {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DefStoreCRLUpdater.class);

    private Hashtable<String, CRLIPContainer> mCache = null;
    private int mSec = 0;

    public DefStoreCRLUpdater(Hashtable<String, CRLIPContainer> cache, int sec) {
        mCache = cache;
        mSec = sec;
    }

    @Override
    public void run() {
        while (true) {
            try {
                logger.debug("DefStore: CRLUpdater invoked");
                mCache.clear();
                sleep(mSec * 1000); // turn sec into millis-sec
            } catch (Exception e) {
                // ignore
            }
        }
    }
}

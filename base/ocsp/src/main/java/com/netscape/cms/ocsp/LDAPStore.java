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
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.RepositoryRecord;
import com.netscape.cmsutil.ocsp.CertID;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.GoodInfo;
import com.netscape.cmsutil.ocsp.Request;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.UnknownInfo;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

/**
 * This is the LDAP OCSP store. It reads CA certificate and
 * revocation list attributes from the CA entry.
 *
 * @version $Revision$, $Date$
 */
public class LDAPStore implements IDefStore, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LDAPStore.class);

    private static final String PROP_NUM_CONNS = "numConns";
    private static final String PROP_REFRESH_IN_SEC = "refreshInSec";
    private static final int DEF_REFRESH_IN_SEC = 60 * 60 * 24;
    private static final String PROP_BASE_DN = "baseDN";
    private static final String PROP_BY_NAME = "byName";
    private static final String PROP_CRL_ATTR = "crlAttr";
    private static final String DEF_CRL_ATTR = "certificateRevocationList;binary";
    private static final String PROP_CA_CERT_ATTR = "caCertAttr";
    private static final String DEF_CA_CERT_ATTR = "cACertificate;binary";
    private static final String PROP_HOST = "host";
    private static final String PROP_PORT = "port";

    private final static String PROP_NOT_FOUND_GOOD = "notFoundAsGood";
    private final static String PROP_INCLUDE_NEXT_UPDATE =
            "includeNextUpdate";

    private ConfigStore mConfig;
    private String mId = null;
    private String mCRLAttr = null;
    private boolean mByName = true;
    private String mCACertAttr = null;
    protected Hashtable<String, Long> mReqCounts = new Hashtable<>();
    private Hashtable<X509CertImpl, X509CRLImpl> mCRLs = new Hashtable<>();

    /**
     * Constructs the default store.
     */
    public LDAPStore() {
    }

    @Override
    public boolean isByName() {
        return mByName;
    }

    @Override
    public String[] getExtendedPluginInfo() {
        return getExtendedPluginInfo(Locale.getDefault());
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        Vector<String> v = new Vector<>();

        v.addElement(PROP_NOT_FOUND_GOOD
                + ";boolean; " + CMS.getUserMessage(locale, "CMS_OCSP_LDAPSTORE_PROP_NOT_FOUND_GOOD"));
        v.addElement(PROP_INCLUDE_NEXT_UPDATE
                + ";boolean; " + CMS.getUserMessage(locale, "CMS_OCSP_LDAPSTORE_PROP_INCLUDE_NEXT_UPDATE"));
        v.addElement(PROP_NUM_CONNS + ";number; " + CMS.getUserMessage(locale, "CMS_OCSP_LDAPSTORE_PROP_NUM_CONNS"));
        v.addElement(PROP_BY_NAME + ";boolean; " + CMS.getUserMessage(locale, "CMS_OCSP_LDAPSTORE_PROP_BY_NAME"));
        v.addElement(PROP_CRL_ATTR + ";string; " + CMS.getUserMessage(locale, "CMS_OCSP_LDAPSTORE_PROP_CRL_ATTR"));
        v.addElement(PROP_CA_CERT_ATTR
                + ";string; " + CMS.getUserMessage(locale, "CMS_OCSP_LDAPSTORE_PROP_CA_CERT_ATTR"));
        v.addElement(IExtendedPluginInfo.HELP_TEXT + "; " + CMS.getUserMessage(locale, "CMS_OCSP_LDAPSTORE_DESC"));
        v.addElement(IExtendedPluginInfo.HELP_TOKEN + ";configuration-ocspstores-ldapstore");
        return org.mozilla.jss.netscape.security.util.Utils.getStringArrayFromVector(v);
    }

    /**
     * Fetch CA certificate and CRL from LDAP server.
     */
    @Override
    public void init(ConfigStore config, DBSubsystem dbSubsystem) throws EBaseException {

        mConfig = config;

        mCRLAttr = mConfig.getString(PROP_CRL_ATTR, DEF_CRL_ATTR);
        mCACertAttr = mConfig.getString(PROP_CA_CERT_ATTR,
                    DEF_CA_CERT_ATTR);
        mByName = mConfig.getBoolean(PROP_BY_NAME, true);

    }

    /**
     * Locates the CA certificate.
     */
    public X509CertImpl locateCACert(LDAPConnection conn, String baseDN)
            throws EBaseException {
        try {
            String filter = mCACertAttr + "=*";
            logger.info("LDAPStore: Searching " + baseDN + " for " + filter);

            LDAPSearchResults results = conn.search(
                    baseDN,
                    LDAPv3.SCOPE_SUB,
                    filter,
                    null, false);

            if (!results.hasMoreElements()) {
                logger.warn("Unable to find entries with CA cert under " + baseDN);
                return null;
            }

            LDAPEntry entry = results.next();
            logger.info("LDAPStore: Getting " + mCACertAttr + " attribute from " + entry.getDN());

            LDAPAttribute caCerts = entry.getAttribute(mCACertAttr);
            if (caCerts == null) {
                logger.warn("Unable to find " + mCACertAttr + " attribute in " + entry.getDN());
                return null;
            }

            Enumeration<byte[]> vals = caCerts.getByteValues();

            if (!vals.hasMoreElements()) {
                logger.warn("Unable to find values of " + mCACertAttr + " attribute in " + entry.getDN());
                return null;
            }

            byte caCertData[] = vals.nextElement();
            X509CertImpl caCert = new X509CertImpl(caCertData);

            return caCert;

        } catch (Exception e) {
            logger.warn("Unable to locate CA certificate: " + e.getMessage(), e);
            logger.warn(CMS.getLogMessage("OCSP_LOCATE_CA", e.toString()));
        }

        return null;
    }

    /**
     * Locates the CRL.
     */
    public X509CRLImpl locateCRL(LDAPConnection conn, String baseDN)
            throws EBaseException {
        try {
            String filter = mCRLAttr + "=*";
            logger.info("LDAPStore: Searching " + baseDN + " for " + filter);

            LDAPSearchResults results = conn.search(
                    baseDN,
                    LDAPv3.SCOPE_SUB,
                    filter,
                    null, false);

            if (!results.hasMoreElements()) {
                logger.warn("Unable to find entries with CRL under " + baseDN);
                return null;
            }

            LDAPEntry entry = results.next();
            logger.info("LDAPStore: Getting " + mCRLAttr + " attribute from " + entry.getDN());

            LDAPAttribute crls = entry.getAttribute(mCRLAttr);
            if (crls == null) {
                logger.warn("Unable to find " + mCRLAttr + " attribute in " + entry.getDN());
                return null;
            }

            Enumeration<byte[]> vals = crls.getByteValues();

            if (!vals.hasMoreElements()) {
                logger.warn("Unable to find values of " + mCRLAttr + " attribute in " + entry.getDN());
                return null;
            }

            byte crlData[] = vals.nextElement();
            X509CRLImpl crl = new X509CRLImpl(crlData);

            return crl;

        } catch (Exception e) {
            logger.warn("LDAPStore: locateCRL " + e.getMessage(), e);
            logger.warn(CMS.getLogMessage("OCSP_LOCATE_CRL", e.toString()));
        }

        return null;
    }

    public void updateCRLHash(X509CertImpl caCert, X509CRLImpl crl)
            throws EBaseException {
        X509CRLImpl oldCRL = mCRLs.get(caCert);

        if (oldCRL != null) {
            if (oldCRL.getThisUpdate().getTime() >= crl.getThisUpdate().getTime()) {
                logger.info("LDAPStore: no update, received CRL is not newer than current CRL");
                return; // no update
            }
        }
        logger.debug("LDAPStore: updateCRLHash: Added '" + caCert.getSubjectName() + "' into CRL hash");
        mCRLs.put(caCert, crl);
        logger.debug("LDAPStore: updateCRLHash: mCRLs size= "+ mCRLs.size());
    }

    @Override
    public void startup() throws EBaseException {
        int num = mConfig.getInteger(PROP_NUM_CONNS, 0);

        for (int i = 0; i < num; i++) {
            String host = mConfig.getString(PROP_HOST + Integer.toString(i), null);
            int port = mConfig.getInteger(PROP_PORT + Integer.toString(i), 0);
            LDAPConnection c = new LDAPConnection();

            try {
                c.connect(host, port);
            } catch (LDAPException e) {
                throw new EBaseException("LDAP " + e);
            }
            String baseDN = mConfig.getString(PROP_BASE_DN + Integer.toString(i), null);
            CRLUpdater updater = new CRLUpdater(
                    this, c, baseDN,
                    mConfig.getInteger(PROP_REFRESH_IN_SEC + Integer.toString(i),
                            DEF_REFRESH_IN_SEC));

            updater.start();
        }
        CMS.setApprovalCallbask(new CRLLdapValidator(this));
    }

    @Override
    public void shutdown() {
    }

    public ConfigStore getConfigStore() {
        return mConfig;
    }

    public void setId(String id) throws EBaseException {
        mId = id;
    }

    public String getId() {
        return mId;
    }


    @Override
    public int getStateCount() {
        return 0;
    }

    @Override
    public long getReqCount(String id) {
        Long c = mReqCounts.get(id);
        return c == null ? 0 : c.longValue();
    }

    @Override
    public RepositoryRecord createRepositoryRecord() {
        return null;
    }

    @Override
    public void addRepository(String name, String thisUpdate,
            RepositoryRecord rec)
            throws EBaseException {
        throw new EBaseException("NOT SUPPORTED");
    }

    @Override
    public boolean waitOnCRLUpdate() {
        return false;
    }

    @Override
    public void updateCRL(X509CRL crl) throws EBaseException {
        throw new EBaseException("NOT SUPPORTED");
    }

    @Override
    public CRLIssuingPointRecord readCRLIssuingPoint(String name)
            throws EBaseException {
        throw new EBaseException("NOT SUPPORTED");
    }

    @Override
    public Enumeration<CRLIssuingPointRecord> searchAllCRLIssuingPointRecord(int maxSize)
            throws EBaseException {
        Vector<CRLIssuingPointRecord> recs = new Vector<>();
        Enumeration<X509CertImpl> keys = mCRLs.keys();

        while (keys.hasMoreElements()) {
            X509CertImpl caCert = keys.nextElement();
            X509CRLImpl crl = mCRLs.get(caCert);

            recs.addElement(new TempCRLIssuingPointRecord(caCert, crl));
        }
        return recs.elements();
    }

    @Override
    public Enumeration<CRLIssuingPointRecord> searchCRLIssuingPointRecord(String filter,
            int maxSize)
            throws EBaseException {
        return null;
    }

    @Override
    public CRLIssuingPointRecord createCRLIssuingPointRecord(
            String name, BigInteger crlNumber,
            Long crlSize, Date thisUpdate, Date nextUpdate) {
        return null;
    }

    @Override
    public void addCRLIssuingPoint(String name, CRLIssuingPointRecord rec)
            throws EBaseException {
        throw new EBaseException("NOT SUPPORTED");
    }

    @Override
    public void deleteCRLIssuingPointRecord(String id)
            throws EBaseException {
        throw new EBaseException("NOT SUPPORTED");
    }

    @Override
    public boolean isNotFoundGood() {
        try {
            return isNotFoundGood1();
        } catch (Exception e) {
            return false;
        }
    }

    public boolean includeNextUpdate() throws EBaseException {
        return mConfig.getBoolean(PROP_INCLUDE_NEXT_UPDATE, false);
    }

    public boolean isNotFoundGood1() throws EBaseException {
        return mConfig.getBoolean(PROP_NOT_FOUND_GOOD, true);
    }

    public void incReqCount(String id) {
        mReqCounts.put(id, Long.valueOf(getReqCount(id) + 1));
    }

    /**
     * Check against the database for status.
     */
    @Override
    public SingleResponse processRequest(Request req) throws Exception {

        CertID cid = req.getCertID();
        INTEGER serialNo = cid.getSerialNumber();
        logger.info("LDAPStore: Processing request for cert 0x" + serialNo.toString(16));

        // locate the right CRL
        X509CertImpl theCert = null;
        X509CRLImpl theCRL = null;

        logger.info("LDAPStore: Checking against " + mCRLs.size() + " CA cert(s)");
        Enumeration<X509CertImpl> caCerts = mCRLs.keys();

        MessageDigest md = MessageDigest.getInstance(cid.getDigestName());
        while (caCerts.hasMoreElements()) {
            X509CertImpl caCert = caCerts.nextElement();
	    logger.debug("LDAPStore: processRequest: cert digest name=" +
                    cid.getDigestName());
            X509Key key = (X509Key) caCert.getPublicKey();

            if (key == null) {
                logger.debug("LDAPStore: processRequest: mCRLs caCert.getPublicKey() returns null");
                throw new Exception("Missing issuer key");
            }

            byte[] digest = md.digest(key.getKey());
            byte[] keyhsh = cid.getIssuerKeyHash().toByteArray();


            byte[] name = md.digest(caCert.getSubjectObj().getX500Name().getEncoded());
            byte[] namehash = cid.getIssuerNameHash().toByteArray();

            if (Arrays.equals(digest, keyhsh) && Arrays.equals(name, namehash)) {
                theCert = caCert;
                incReqCount(caCert.getSubjectX500Principal().getName());
                theCRL = mCRLs.get(caCert);
                break;
            }
            logger.debug("LDAPStore: processRequest: CA key digest and cert issuer key hash do not match; continue to look at next CA in mCRLs...");
        }

        if (theCert == null) {
            logger.warn("Missing issuer certificate");
            // Unknown cert so respond with unknown state
            return new SingleResponse(cid, new UnknownInfo(), new GeneralizedTime(new Date()), null);
        }

        if (theCRL == null) {
            throw new Exception("Missing CRL data for issuing CA:" +
                    theCert.getSubjectDN());
        }

        GeneralizedTime thisUpdate = new GeneralizedTime(
                theCRL.getThisUpdate());
        GeneralizedTime nextUpdate = null;

        if (includeNextUpdate()) {
            nextUpdate = new GeneralizedTime(
                        theCRL.getNextUpdate());
        }

        CertStatus certStatus = null;
        X509CRLEntry entry = theCRL.getRevokedCertificate(
                cid.getSerialNumber());

        if (entry == null) {
            if (isNotFoundGood1()) {
                certStatus = new GoodInfo();
            } else {
                certStatus = new UnknownInfo();
            }
        } else {
            certStatus = new RevokedInfo(new GeneralizedTime(
                            entry.getRevocationDate()));
        }

        return new SingleResponse(cid, certStatus, thisUpdate, nextUpdate);
    }

    /**
     * Provides configuration parameters.
     */
    @Override
    public NameValuePairs getConfigParameters() {
        try {
            NameValuePairs params = new NameValuePairs();

            params.put(Constants.PR_OCSPSTORE_IMPL_NAME,
                    mConfig.getString("class"));
            int num = mConfig.getInteger(PROP_NUM_CONNS, 0);

            params.put(PROP_NUM_CONNS, Integer.toString(num));
            for (int i = 0; i < num; i++) {
                params.put(PROP_HOST + Integer.toString(i),
                        mConfig.getString(PROP_HOST +
                                Integer.toString(i), ""));
                params.put(PROP_PORT + Integer.toString(i),
                        mConfig.getString(PROP_PORT +
                                Integer.toString(i), "389"));
                params.put(PROP_BASE_DN + Integer.toString(i),
                        mConfig.getString(PROP_BASE_DN +
                                Integer.toString(i), ""));
                params.put(PROP_REFRESH_IN_SEC + Integer.toString(i),
                        mConfig.getString(PROP_REFRESH_IN_SEC +
                                Integer.toString(i), Integer.toString(DEF_REFRESH_IN_SEC)));
            }
            params.put(PROP_BY_NAME,
                    mConfig.getString(PROP_BY_NAME, "true"));
            params.put(PROP_CA_CERT_ATTR,
                    mConfig.getString(PROP_CA_CERT_ATTR, DEF_CA_CERT_ATTR));
            params.put(PROP_CRL_ATTR,
                    mConfig.getString(PROP_CRL_ATTR, DEF_CRL_ATTR));
            params.put(PROP_NOT_FOUND_GOOD,
                    mConfig.getString(PROP_NOT_FOUND_GOOD, "true"));
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
}

class CRLUpdater extends Thread {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CRLUpdater.class);

    private LDAPConnection mC = null;
    private String mBaseDN = null;
    private int mSec = 0;
    private LDAPStore mStore = null;

    public CRLUpdater(LDAPStore store, LDAPConnection c,
            String baseDN, int sec) {
        mC = c;
        mSec = sec;
        mBaseDN = baseDN;
        mStore = store;
    }

    public void updateCRLCache() throws EBaseException {

        logger.info("LDAPStore: Updating CRL");

        X509CertImpl caCert = mStore.locateCACert(mC, mBaseDN);
        if (caCert == null) {
            logger.info("LDAPStore: Unable to find CA cert");
            return;
        }

        X509CRLImpl crl = mStore.locateCRL(mC, mBaseDN);
        if (crl == null) {
            logger.info("LDAPStore: Unable to find CRL");
            return;
        }

        logger.info("LDAPStore: Updating CRL cache");
        mStore.updateCRLHash(caCert, crl);
    }

    @Override
    public void run() {
        while (true) {
            try {
                updateCRLCache();
            } catch (Exception e) {
                logger.error("Unable to update CRL cache: " + e.getMessage(), e);
            }

            try {
                sleep(mSec * 1000); // turn sec into millis-sec
            } catch (Exception e) {
                // ignore
            }
        }
    }
}

class TempCRLIssuingPointRecord extends CRLIssuingPointRecord {

    private static final long serialVersionUID = 5299660983298765746L;
    private X509CertImpl mCACert = null;
    private X509CRLImpl mCRL = null;

    TempCRLIssuingPointRecord(X509CertImpl caCert, X509CRLImpl crl) {
        mCACert = caCert;
        mCRL = crl;
    }

    @Override
    public String getId() {
        return mCACert.getSubjectName().toString();
    }

    /**
     * Retrieves CRL serial number.
     */
    @Override
    public BigInteger getCRLNumber() {
        return null;
    }

    /**
     * Retrieves delta CRL serial number.
     */
    @Override
    public BigInteger getDeltaCRLNumber() {
        return null;
    }

    /**
     * Retrieves CRL size.
     */
    @Override
    public Long getCRLSize() {
        return Long.valueOf(mCRL.getNumberOfRevokedCertificates());
    }

    /**
     * Retrieves CRL size.
     */
    @Override
    public Long getDeltaCRLSize() {
        return Long.valueOf(-1);
    }

    /**
     * Retrieves this update time.
     */
    @Override
    public Date getThisUpdate() {
        return mCRL.getThisUpdate();
    }

    /**
     * Retrieves next update time.
     */
    @Override
    public Date getNextUpdate() {
        return mCRL.getNextUpdate();
    }

    @Override
    public String getFirstUnsaved() {
        return null;
    }

    @Override
    public Hashtable<BigInteger, RevokedCertificate> getCRLCacheNoClone() {
        return null;
    }

    @Override
    public Hashtable<BigInteger, RevokedCertificate> getCRLCache() {
        return null;
    }

    /**
     * Retrieves CRL encodings.
     */
    @Override
    public byte[] getCRL() {
        try {
            return mCRL.getEncoded();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Retrieves CRL encodings.
     */
    @Override
    public byte[] getDeltaCRL() {
        return null;
    }

    public int isCRLIssuingPointInitialized() {
        return 1;
    }

    @Override
    public byte[] getCACert() {
        try {
            return mCACert.getEncoded();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Retrieves cache info of revoked certificates.
     */
    @Override
    public Hashtable<BigInteger, RevokedCertificate> getRevokedCerts() {
        return mCRL.getListOfRevokedCertificates();
    }

    /**
     * Retrieves cache info of unrevoked certificates.
     */
    @Override
    public Hashtable<BigInteger, RevokedCertificate> getUnrevokedCerts() {
        return null;
    }

    /**
     * Retrieves cache info of expired certificates.
     */
    @Override
    public Hashtable<BigInteger, RevokedCertificate> getExpiredCerts() {
        return null;
    }

    @Override
    public Enumeration<String> getSerializableAttrNames() {
        return null;
    }

    @Override
    public void set(String name, Object obj) throws EBaseException {
    }

    @Override
    public Object get(String name) throws EBaseException {
        return null;
    }

    @Override
    public void delete(String name) throws EBaseException {

    }

    @Override
    public Enumeration<String> getElements() {
        return null;
    }
}

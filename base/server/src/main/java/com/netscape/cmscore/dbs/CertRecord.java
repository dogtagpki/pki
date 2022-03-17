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
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.cmscore.apps.CMS;

/**
 * A class represents a serializable certificate record.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CertRecord implements IDBObj {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRecord.class);

    private static final long serialVersionUID = -6231895305929417777L;

    public final static String ATTR_ID = "certRecordId";
    public final static String ATTR_META_INFO = "certMetaInfo";
    public final static String ATTR_REVO_INFO = "certRevoInfo";
    public final static String ATTR_CERT_STATUS = "certStatus";
    public final static String ATTR_CREATE_TIME = "certCreateTime";
    public final static String ATTR_MODIFY_TIME = "certModifyTime";
    public final static String ATTR_AUTO_RENEW = "certAutoRenew";
    public final static String ATTR_ISSUED_BY = "certIssuedBy";
    public final static String ATTR_REVOKED_BY = "certRevokedBy";
    public final static String ATTR_REVOKED_ON = "certRevokedOn";
    public final static String ATTR_X509CERT = "x509cert";

    public static final String META_LDAPPUBLISH = "inLdapPublishDir";
    public static final String META_REQUEST_ID = "requestId";
    public static final String META_RENEWED_CERT = "renewedCertSerialNo";
    public static final String META_OLD_CERT = "oldCertSerialNo";
    public static final String META_CERT_TYPE = "certType";
    public static final String META_CRMF_REQID = "crmfReqId";
    public static final String META_CHALLENGE_PHRASE = "challengePhrase";
    public static final String META_PROFILE_ID = "profileId";
    // for supporting CMC shared-secret based revocation
    public static final String META_REV_SHRTOK = "revShrTok";

    public final static String STATUS_VALID = "VALID";
    public final static String STATUS_INVALID = "INVALID";
    public final static String STATUS_REVOKED = "REVOKED";
    public final static String STATUS_EXPIRED = "EXPIRED";
    public final static String STATUS_REVOKED_EXPIRED = "REVOKED_EXPIRED";

    public final static String AUTO_RENEWAL_DISABLED = "DISABLED";
    public final static String AUTO_RENEWAL_ENABLED = "ENABLED";
    public final static String AUTO_RENEWAL_DONE = "DONE";
    public final static String AUTO_RENEWAL_NOTIFIED = "NOTIFIED";

    public final static String X509CERT_NOT_BEFORE = "notBefore";
    public final static String X509CERT_NOT_AFTER = "notAfter";
    public final static String X509CERT_DURATION = "duration";
    public final static String X509CERT_EXTENSION = "extension";
    public final static String X509CERT_SUBJECT = "subject";
    public final static String X509CERT_ISSUER = "issuer";
    public final static String X509CERT_PUBLIC_KEY_DATA = "publicKeyData";
    public final static String X509CERT_VERSION = "version";
    public final static String X509CERT_ALGORITHM = "algorithm";
    public final static String X509CERT_SIGNING_ALGORITHM = "signingAlgorithm";
    public final static String X509CERT_SERIAL_NUMBER = "serialNumber";

    /* attribute type used the following with search filter */
    public final static String ATTR_X509CERT_NOT_BEFORE =
            ATTR_X509CERT + "." + X509CERT_NOT_BEFORE;
    public final static String ATTR_X509CERT_NOT_AFTER =
            ATTR_X509CERT + "." + X509CERT_NOT_AFTER;
    public final static String ATTR_X509CERT_DURATION =
            ATTR_X509CERT + "." + X509CERT_DURATION;
    public final static String ATTR_X509CERT_EXTENSION =
            ATTR_X509CERT + "." + X509CERT_EXTENSION;
    public final static String ATTR_X509CERT_SUBJECT =
            ATTR_X509CERT + "." + X509CERT_SUBJECT;
    public final static String ATTR_X509CERT_ISSUER =
            ATTR_X509CERT + "." + X509CERT_ISSUER;
    public final static String ATTR_X509CERT_VERSION =
            ATTR_X509CERT + "." + X509CERT_VERSION;
    public final static String ATTR_X509CERT_ALGORITHM =
            ATTR_X509CERT + "." + X509CERT_ALGORITHM;
    public final static String ATTR_X509CERT_SIGNING_ALGORITHM =
            ATTR_X509CERT + "." + X509CERT_SIGNING_ALGORITHM;
    public final static String ATTR_X509CERT_SERIAL_NUMBER =
            ATTR_X509CERT + "." + X509CERT_SERIAL_NUMBER;
    public final static String ATTR_X509CERT_PUBLIC_KEY_DATA =
            ATTR_X509CERT + "." + X509CERT_PUBLIC_KEY_DATA;

    private BigInteger mId = null;
    private X509CertImpl mX509Certificate = null;
    private String mStatus = null;
    private String mAutoRenew = null;
    private MetaInfo mMetaInfo = null;
    // XXX revocationInfo not serializable
    private transient RevocationInfo mRevocationInfo = null;
    private Date mCreateTime = null;
    private Date mModifyTime = null;
    private String mIssuedBy = null;
    private String mRevokedBy = null;
    private Date mRevokedOn = null;

    protected static Vector<String> mNames = new Vector<>();
    static {
        mNames.addElement(ATTR_ID);
        mNames.addElement(ATTR_META_INFO);
        mNames.addElement(ATTR_REVO_INFO);
        mNames.addElement(ATTR_X509CERT);
        mNames.addElement(ATTR_CREATE_TIME);
        mNames.addElement(ATTR_MODIFY_TIME);
        mNames.addElement(ATTR_CERT_STATUS);
        mNames.addElement(ATTR_AUTO_RENEW);
        mNames.addElement(ATTR_ISSUED_BY);
        mNames.addElement(ATTR_REVOKED_BY);
        mNames.addElement(ATTR_REVOKED_ON);
    }

    /**
     * Constructs empty certificate record.
     */
    public CertRecord() {
    }

    /**
     * Constructs certiificate record with certificate
     * and meta info.
     */
    public CertRecord(BigInteger id, Certificate cert, MetaInfo meta) {
        mId = id;
        if (cert instanceof X509CertImpl)
            mX509Certificate = (X509CertImpl) cert;
        mMetaInfo = meta;
        mStatus = STATUS_VALID;
        mAutoRenew = AUTO_RENEWAL_ENABLED;
        mCreateTime = new Date();
        mModifyTime = new Date();
    }

    /**
     * Sets attribute to this record.
     */
    @Override
    public void set(String name, Object obj) throws EBaseException {
        if (name.equalsIgnoreCase(ATTR_REVO_INFO)) {
            mRevocationInfo = (RevocationInfo) obj;
        } else if (name.equalsIgnoreCase(ATTR_ID)) {
            mId = (BigInteger) obj;
        } else if (name.equalsIgnoreCase(ATTR_META_INFO)) {
            mMetaInfo = (MetaInfo) obj;
        } else if (name.equalsIgnoreCase(ATTR_X509CERT)) {
            mX509Certificate = (X509CertImpl) obj;
        } else if (name.equalsIgnoreCase(ATTR_CERT_STATUS)) {
            mStatus = (String) obj;
        } else if (name.equalsIgnoreCase(ATTR_AUTO_RENEW)) {
            mAutoRenew = (String) obj;
        } else if (name.equalsIgnoreCase(ATTR_CREATE_TIME)) {
            mCreateTime = (Date) obj;
        } else if (name.equalsIgnoreCase(ATTR_MODIFY_TIME)) {
            mModifyTime = (Date) obj;
        } else if (name.equalsIgnoreCase(ATTR_ISSUED_BY)) {
            mIssuedBy = (String) obj;
        } else if (name.equalsIgnoreCase(ATTR_REVOKED_BY)) {
            mRevokedBy = (String) obj;
        } else if (name.equalsIgnoreCase(ATTR_REVOKED_ON)) {
            mRevokedOn = (Date) obj;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    /**
     * Retrieves attributes from this record.
     */
    @Override
    public Object get(String name) throws EBaseException {
        if (name.equalsIgnoreCase(ATTR_REVO_INFO)) {
            return mRevocationInfo;
        } else if (name.equalsIgnoreCase(ATTR_ID)) {
            return mId;
        } else if (name.equalsIgnoreCase(ATTR_META_INFO)) {
            return mMetaInfo;
        } else if (name.equalsIgnoreCase(ATTR_X509CERT)) {
            return mX509Certificate;
        } else if (name.equalsIgnoreCase(ATTR_CERT_STATUS)) {
            return mStatus;
        } else if (name.equalsIgnoreCase(ATTR_AUTO_RENEW)) {
            return mAutoRenew;
        } else if (name.equalsIgnoreCase(ATTR_CREATE_TIME)) {
            return mCreateTime;
        } else if (name.equalsIgnoreCase(ATTR_MODIFY_TIME)) {
            return mModifyTime;
        } else if (name.equalsIgnoreCase(ATTR_ISSUED_BY)) {
            return mIssuedBy;
        } else if (name.equalsIgnoreCase(ATTR_REVOKED_BY)) {
            return mRevokedBy;
        } else if (name.equalsIgnoreCase(ATTR_REVOKED_ON)) {
            return mRevokedOn;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    /**
     * Deletes attribute from this record.
     */
    @Override
    public void delete(String name) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
    }

    @Override
    public Enumeration<String> getElements() {
        return mNames.elements();
    }

    @Override
    public Enumeration<String> getSerializableAttrNames() {
        return mNames.elements();
    }

    /**
     * Retrieves certificate from certificate record.
     *
     * @return certificate
     */
    public X509CertImpl getCertificate() {
        return mX509Certificate;
    }

    /**
     * Retrieves meta information.
     *
     * @return meta information
     */
    public MetaInfo getMetaInfo() {
        return mMetaInfo;
    }

    /**
     * Retrieves certificate status.
     *
     * @return certificate status
     */
    public String getStatus() {
        return mStatus;
    }

    /**
     * Retrieves the auto renew mode.
     */
    public String getAutoRenew() {
        return mAutoRenew;
    }

    /**
     * Retrieves revocation information.
     *
     * @return revocation information
     */
    public RevocationInfo getRevocationInfo() {
        return mRevocationInfo;
    }

    /**
     * Retrieves serial number of this record. Usually,
     * it is the same of the serial number of the
     * associated certificate.
     *
     * @return certificate serial number
     */
    public BigInteger getSerialNumber() {
        return mId;
    }

    /**
     * Retrieves name of which user issued this certificate.
     *
     * @return name of which user issued this certificate
     */
    public String getIssuedBy() {
        return mIssuedBy;
    }

    /**
     * Retrieves name of who revoked this certificate.
     *
     * @return name of who revoked this certificate
     */
    public String getRevokedBy() {
        return mRevokedBy;
    }

    /**
     * Retrieves date when this certificate was revoked.
     *
     * @return date when this certificate was revoked
     */
    public Date getRevokedOn() {
        return mRevokedOn;
    }

    /**
     * Retrieves serial number from stored certificate.
     *
     * @return certificate serial number
     */
    public BigInteger getCertificateSerialNumber() {
        return mX509Certificate.getSerialNumber();
    }

    /**
     * Retrieves not after.
     */
    public Date getNotAfter() {
        return mX509Certificate.getNotAfter();
    }

    public Date getNotBefore() {
        return mX509Certificate.getNotBefore();
    }

    /**
     * Return revocation date.
     */
    public Date getRevocationDate() throws EDBException {
        return mRevocationInfo.getRevocationDate();
    }

    /**
     * Retrieves time of creation of this certificate record.
     *
     * @return time of creation of this certificate record
     */
    public Date getCreateTime() {
        return mCreateTime;
    }

    /**
     * Retrieves time of modification of this certificate record.
     *
     * @return time of modification of this certificate record
     */
    public Date getModifyTime() {
        return mModifyTime;
    }

    /*
     * Returns the revocation reason.
     *
     * @returns RevocationReason if cert is revoked; null if not
     * it throws exceptions if anything failed
     */
    public RevocationReason getRevReason()
            throws EBaseException, X509ExtensionException {
        String method = "CertRecord.getRevReason:";
        String msg = "";
        // logger.debug(method + " checking for cert serial: "
        //        + getSerialNumber().toString());
        RevocationInfo revInfo = getRevocationInfo();
        if (revInfo == null) {
            msg = "revInfo null for" + getSerialNumber().toString();
            logger.debug(method + msg);
            return null;
        }

        CRLExtensions crlExts = revInfo.getCRLEntryExtensions();
        if (crlExts == null)
            throw new X509ExtensionException("crlExts null");

        CRLReasonExtension reasonExt = null;
        reasonExt = (CRLReasonExtension) crlExts.get(CRLReasonExtension.NAME);
        if (reasonExt == null)
            throw new EBaseException("reasonExt null");

        return reasonExt.getReason();
    }

    /**
     * Is this cert on hold?
     */
    public boolean isCertOnHold() {
        String method = "CertRecord.isCertOnHold: ";
        logger.debug(method + "checking for cert serial: "
                + getSerialNumber().toString());
        try {
            RevocationReason revReason = getRevReason();
            if (revReason == RevocationReason.CERTIFICATE_HOLD) {
                logger.debug(method + "for " + getSerialNumber().toString() + " returning true");
                return true;
            }
        } catch (Exception e) {
            logger.warn(method + e.getMessage(), e);
        }
        logger.debug(method + "for " + getSerialNumber().toString() + " returning false");
        return false;
    }

    /**
     * String representation
     */
    @Override
    public String toString() {
        StringBuffer buf = new StringBuffer("CertRecord: ");

        if (getSerialNumber() != null)
            buf.append("    " + getSerialNumber().toString());
        return buf.toString();
    }
}

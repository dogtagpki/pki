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
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
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

    private static final String CMS_BASE_INVALID_ATTRIBUTE = "CMS_BASE_INVALID_ATTRIBUTE";

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRecord.class);

    private static final long serialVersionUID = -6231895305929417777L;

    public static final String ATTR_ID = "certRecordId";
    public static final String ATTR_META_INFO = "certMetaInfo";
    public static final String ATTR_REVO_INFO = "certRevoInfo";
    public static final String ATTR_CERT_STATUS = "certStatus";
    public static final String ATTR_CREATE_TIME = "certCreateTime";
    public static final String ATTR_MODIFY_TIME = "certModifyTime";
    public static final String ATTR_AUTO_RENEW = "certAutoRenew";
    public static final String ATTR_ISSUED_BY = "certIssuedBy";
    public static final String ATTR_REVOKED_BY = "certRevokedBy";
    public static final String ATTR_REVOKED_ON = "certRevokedOn";
    public static final String ATTR_X509CERT = "x509cert";

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

    public static final String STATUS_VALID = "VALID";
    public static final String STATUS_INVALID = "INVALID";
    public static final String STATUS_REVOKED = "REVOKED";
    public static final String STATUS_EXPIRED = "EXPIRED";
    public static final String STATUS_REVOKED_EXPIRED = "REVOKED_EXPIRED";

    public static final String AUTO_RENEWAL_DISABLED = "DISABLED";
    public static final String AUTO_RENEWAL_ENABLED = "ENABLED";
    public static final String AUTO_RENEWAL_DONE = "DONE";
    public static final String AUTO_RENEWAL_NOTIFIED = "NOTIFIED";

    public static final String X509CERT_NOT_BEFORE = "notBefore";
    public static final String X509CERT_NOT_AFTER = "notAfter";
    public static final String X509CERT_DURATION = "duration";
    public static final String X509CERT_EXTENSION = "extension";
    public static final String X509CERT_SUBJECT = "subject";
    public static final String X509CERT_ISSUER = "issuer";
    public static final String X509CERT_PUBLIC_KEY_DATA = "publicKeyData";
    public static final String X509CERT_VERSION = "version";
    public static final String X509CERT_ALGORITHM = "algorithm";
    public static final String X509CERT_SIGNING_ALGORITHM = "signingAlgorithm";
    public static final String X509CERT_SERIAL_NUMBER = "serialNumber";

    /* attribute type used the following with search filter */
    public static final String ATTR_X509CERT_NOT_BEFORE = ATTR_X509CERT + "." + X509CERT_NOT_BEFORE;
    public static final String ATTR_X509CERT_NOT_AFTER = ATTR_X509CERT + "." + X509CERT_NOT_AFTER;
    public static final String ATTR_X509CERT_DURATION = ATTR_X509CERT + "." + X509CERT_DURATION;
    public static final String ATTR_X509CERT_EXTENSION = ATTR_X509CERT + "." + X509CERT_EXTENSION;
    public static final String ATTR_X509CERT_SUBJECT = ATTR_X509CERT + "." + X509CERT_SUBJECT;
    public static final String ATTR_X509CERT_ISSUER = ATTR_X509CERT + "." + X509CERT_ISSUER;
    public static final String ATTR_X509CERT_VERSION = ATTR_X509CERT + "." + X509CERT_VERSION;
    public static final String ATTR_X509CERT_ALGORITHM = ATTR_X509CERT + "." + X509CERT_ALGORITHM;
    public static final String ATTR_X509CERT_SIGNING_ALGORITHM = ATTR_X509CERT + "." + X509CERT_SIGNING_ALGORITHM;
    public static final String ATTR_X509CERT_SERIAL_NUMBER = ATTR_X509CERT + "." + X509CERT_SERIAL_NUMBER;
    public static final String ATTR_X509CERT_PUBLIC_KEY_DATA = ATTR_X509CERT + "." + X509CERT_PUBLIC_KEY_DATA;

    private BigInteger mId = null;
    private X509CertImpl mX509Certificate = null;
    private String mStatus = null;
    private String mAutoRenew = null;
    private MetaInfo mMetaInfo = null;
    // revocationInfo not serializable
    private transient RevocationInfo mRevocationInfo = null;
    private Date mCreateTime = null;
    private Date mModifyTime = null;
    private String mIssuedBy = null;
    private String mRevokedBy = null;
    private Date mRevokedOn = null;

    protected static List<String> mNames = Arrays.asList(
            ATTR_ID, ATTR_META_INFO, ATTR_REVO_INFO, ATTR_X509CERT, ATTR_CREATE_TIME, ATTR_MODIFY_TIME,
            ATTR_CERT_STATUS, ATTR_AUTO_RENEW, ATTR_ISSUED_BY, ATTR_REVOKED_BY, ATTR_REVOKED_ON);

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
        if (cert instanceof X509CertImpl x509Cert)
            mX509Certificate = x509Cert;
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
            throw new EBaseException(CMS.getUserMessage(CMS_BASE_INVALID_ATTRIBUTE, name));
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
            throw new EBaseException(CMS.getUserMessage(CMS_BASE_INVALID_ATTRIBUTE, name));
        }
    }

    /**
     * Deletes attribute from this record.
     */
    @Override
    public void delete(String name) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage(CMS_BASE_INVALID_ATTRIBUTE, name));
    }

    @Override
    public Enumeration<String> getElements() {
        return Collections.enumeration(mNames);
    }

    @Override
    public Enumeration<String> getSerializableAttrNames() {
        return Collections.enumeration(mNames);
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
    public Date getRevocationDate() {
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
        RevocationInfo revInfo = getRevocationInfo();
        if (revInfo == null) {
            String msg = "revInfo null for" + getSerialNumber().toString();
            logger.debug("CertRecord.getRevReason: {}", msg);
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
        logger.debug("{} checking for cert serial: {}", method, getSerialNumber());
        try {
            RevocationReason revReason = getRevReason();
            if (revReason == RevocationReason.CERTIFICATE_HOLD) {
                logger.debug("{} for {} returning true", method, getSerialNumber());
                return true;
            }
        } catch (Exception e) {
            logger.warn("{} {}", method, e.getMessage(), e);
        }
        logger.debug("{} for {} returning false", method, getSerialNumber());
        return false;
    }

    /**
     * String representation
     */
    @Override
    public String toString() {
        String certRecordString = "CertRecord: ";

        if (getSerialNumber() != null)
            certRecordString = certRecordString.concat("    " + getSerialNumber().toString());
        return certRecordString;
    }
}

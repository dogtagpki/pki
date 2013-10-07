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

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.IRevocationInfo;

/**
 * A class represents a serializable certificate record.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CertRecord implements IDBObj, ICertRecord {

    /**
     *
     */
    private static final long serialVersionUID = -6231895305929417777L;
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

    protected static Vector<String> mNames = new Vector<String>();
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
        mCreateTime = CMS.getCurrentDate();
        mModifyTime = CMS.getCurrentDate();
    }

    /**
     * Sets attribute to this record.
     */
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
    public void delete(String name) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
    }

    public Enumeration<String> getElements() {
        return mNames.elements();
    }

    public Enumeration<String> getSerializableAttrNames() {
        return mNames.elements();
    }

    /**
     * Retrieves X509 certificate.
     */
    public X509CertImpl getCertificate() {
        return mX509Certificate;
    }

    /**
     * Retrieves meta information.
     */
    public MetaInfo getMetaInfo() {
        return mMetaInfo;
    }

    /**
     * Retrieves certificate status.
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
     */
    public IRevocationInfo getRevocationInfo() {
        return mRevocationInfo;
    }

    /**
     * Retrieves serial number of this record. Usually,
     * it is the same of the serial number of the
     * associated certificate.
     */
    public BigInteger getSerialNumber() {
        return mId;
    }

    /**
     * Retrieves the person who issues this certificate.
     */
    public String getIssuedBy() {
        return mIssuedBy;
    }

    /**
     * Retrieves the person who revokes this certificate.
     */
    public String getRevokedBy() {
        return mRevokedBy;
    }

    /**
     * Retrieves the date which this record is revoked.
     */
    public Date getRevokedOn() {
        return mRevokedOn;
    }

    /**
     * Retrieves certificate serial number.
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

    public Date getCreateTime() {
        return mCreateTime;
    }

    public Date getModifyTime() {
        return mModifyTime;
    }

    /**
     * String representation
     */
    public String toString() {
        StringBuffer buf = new StringBuffer("CertRecord: ");

        if (getSerialNumber() != null)
            buf.append("    " + getSerialNumber().toString());
        return buf.toString();
    }
}

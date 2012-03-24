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
package com.netscape.certsrv.dbs.certdb;


import java.util.Date;
import java.math.BigInteger;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.base.MetaInfo;
import netscape.security.x509.X509CertImpl;


/**
 * An interface contains constants for certificate record.
 *
 * @version $Revision$, $Date$
 */
public interface ICertRecord extends IDBObj {

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
    public final static String X509CERT_PUBLIC_KEY_DATA ="publicKeyData";
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

    /**
     * Retrieves serial number from stored certificate.
     *
     * @return certificate serial number
     */
    public BigInteger getCertificateSerialNumber();

    /**
     * Retrieves serial number from certificate record.
     *
     * @return certificate serial number
     */
    public BigInteger getSerialNumber();

    /**
     * Retrieves certificate from certificate record.
     *
     * @return certificate
     */
    public X509CertImpl getCertificate();

    /**
     * Retrieves name of who issued this certificate.
     *
     * @return name of who issued this certificate
     */
    public String getIssuedBy();

    /**
     * Retrieves name of who revoked this certificate.
     *
     * @return name of who revoked this certificate
     */
    public String getRevokedBy();

    /**
     * Retrieves date when this certificate was revoked.
     *
     * @return date when this certificate was revoked
     */
    public Date getRevokedOn();

    /**
     * Retrieves meta info.
     *
     * @return meta info
     */
    public MetaInfo getMetaInfo();

    /**
     * Retrieves certificate status.
     *
     * @return certificate status
     */
    public String getStatus();

    /**
     * Retrieves time of creation of this certificate record.
     *
     * @return time of creation of this certificate record
     */
    public Date getCreateTime();

    /**
     * Retrieves time of modification of this certificate record.
     *
     * @return time of modification of this certificate record
     */
    public Date getModifyTime();

    /**
     * Retrieves revocation info.
     *
     * @return revocation info
     */
    public IRevocationInfo getRevocationInfo();
}    

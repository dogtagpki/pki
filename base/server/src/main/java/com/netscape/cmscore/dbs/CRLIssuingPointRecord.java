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
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.RevokedCertificate;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;

/**
 * A class represents a CRL issuing point record.
 *
 * @author thomask
 */
public class CRLIssuingPointRecord extends DBRecord {

    private static final long serialVersionUID = 400565044343905267L;

    public static final String ATTR_ID = "id";
    public static final String ATTR_CRL_NUMBER = "crlNumber";
    public static final String ATTR_DELTA_NUMBER = "deltaNumber";
    public static final String ATTR_CRL_SIZE = "crlSize";
    public static final String ATTR_DELTA_SIZE = "deltaSize";
    public static final String ATTR_THIS_UPDATE = "thisUpdate";
    public static final String ATTR_NEXT_UPDATE = "nextUpdate";
    public static final String ATTR_FIRST_UNSAVED = "firstUnsaved";
    public static final String ATTR_CRL = "certificaterevocationlist";
    public static final String ATTR_CRL_CACHE = "crlCache";
    public static final String ATTR_CA_CERT = "cACertificate";
    public static final String ATTR_REVOKED_CERTS = "revokedCerts";
    public static final String ATTR_UNREVOKED_CERTS = "unrevokedCerts";
    public static final String ATTR_EXPIRED_CERTS = "expiredCerts";
    public static final String ATTR_DELTA_CRL = "deltaRevocationList";

    public static final String CLEAN_CACHE = "-1";
    public static final String NEW_CACHE = "-2";

    protected String mId = null; // internal unique id
    protected BigInteger mCRLNumber = null; // CRL number
    protected Long mCRLSize = null;
    protected Date mThisUpdate = null;
    protected Date mNextUpdate = null;
    protected BigInteger mDeltaCRLNumber = null; // delta CRL number
    protected Long mDeltaCRLSize = null;
    protected String mFirstUnsaved = null;
    protected byte mCRL[] = null;
    protected byte mCACert[] = null;
    protected Hashtable<BigInteger, RevokedCertificate> mCRLCache = null;
    protected Hashtable<BigInteger, RevokedCertificate> mRevokedCerts = null;
    protected Hashtable<BigInteger, RevokedCertificate> mUnrevokedCerts = null;
    protected Hashtable<BigInteger, RevokedCertificate> mExpiredCerts = null;
    protected byte mDeltaCRL[] = null;
    protected static Vector<String> mNames = new Vector<>();
    static {
        mNames.addElement(ATTR_ID);
        mNames.addElement(ATTR_CRL_NUMBER);
        mNames.addElement(ATTR_DELTA_NUMBER);
        mNames.addElement(ATTR_CRL_SIZE);
        mNames.addElement(ATTR_DELTA_SIZE);
        mNames.addElement(ATTR_THIS_UPDATE);
        mNames.addElement(ATTR_NEXT_UPDATE);
        mNames.addElement(ATTR_FIRST_UNSAVED);
        mNames.addElement(ATTR_CRL);
        mNames.addElement(ATTR_CA_CERT);
        mNames.addElement(ATTR_CRL_CACHE);
        mNames.addElement(ATTR_REVOKED_CERTS);
        mNames.addElement(ATTR_UNREVOKED_CERTS);
        mNames.addElement(ATTR_EXPIRED_CERTS);
        mNames.addElement(ATTR_DELTA_CRL);
    }

    /**
     * Constructs empty CRLIssuingPointRecord. This is
     * required in database framework.
     */
    public CRLIssuingPointRecord() {
    }

    /**
     * Constructs a CRLIssuingPointRecord
     */
    public CRLIssuingPointRecord(String id, BigInteger crlNumber, Long crlSize,
            Date thisUpdate, Date nextUpdate) {
        mId = id;
        mCRLNumber = crlNumber;
        mCRLSize = crlSize;
        mThisUpdate = thisUpdate;
        mNextUpdate = nextUpdate;
        mDeltaCRLNumber = BigInteger.ZERO;
        mFirstUnsaved = NEW_CACHE;
        mDeltaCRLSize = Long.valueOf(-1L);
        mCRLCache = null;
        mRevokedCerts = null;
        mUnrevokedCerts = null;
        mExpiredCerts = null;
    }

    /**
     * Constructs a CRLIssuingPointRecord
     */
    public CRLIssuingPointRecord(String id, BigInteger crlNumber, Long crlSize,
            Date thisUpdate, Date nextUpdate, BigInteger deltaCRLNumber, Long deltaCRLSize,
            Hashtable<BigInteger, RevokedCertificate> revokedCerts,
            Hashtable<BigInteger, RevokedCertificate> unrevokedCerts,
            Hashtable<BigInteger, RevokedCertificate> expiredCerts) {
        mId = id;
        mCRLNumber = crlNumber;
        mCRLSize = crlSize;
        mThisUpdate = thisUpdate;
        mNextUpdate = nextUpdate;
        mDeltaCRLNumber = deltaCRLNumber;
        mDeltaCRLSize = deltaCRLSize;
        mFirstUnsaved = NEW_CACHE;
        mCRLCache = null;
        mRevokedCerts = revokedCerts;
        mUnrevokedCerts = unrevokedCerts;
        mExpiredCerts = expiredCerts;
    }

    @Override
    @SuppressWarnings({ "unchecked" })
    public void set(String name, Object obj) throws EBaseException {
        if (name.equalsIgnoreCase(ATTR_ID)) {
            mId = (String) obj;
        } else if (name.equalsIgnoreCase(ATTR_CRL_NUMBER)) {
            mCRLNumber = (BigInteger) obj;
        } else if (name.equalsIgnoreCase(ATTR_CRL_SIZE)) {
            mCRLSize = (Long) obj;
        } else if (name.equalsIgnoreCase(ATTR_THIS_UPDATE)) {
            mThisUpdate = (Date) obj;
        } else if (name.equalsIgnoreCase(ATTR_NEXT_UPDATE)) {
            mNextUpdate = (Date) obj;
        } else if (name.equalsIgnoreCase(ATTR_DELTA_NUMBER)) {
            mDeltaCRLNumber = (BigInteger) obj;
        } else if (name.equalsIgnoreCase(ATTR_DELTA_SIZE)) {
            mDeltaCRLSize = (Long) obj;
        } else if (name.equalsIgnoreCase(ATTR_FIRST_UNSAVED)) {
            mFirstUnsaved = (String) obj;
        } else if (name.equalsIgnoreCase(ATTR_CRL)) {
            mCRL = (byte[]) obj;
        } else if (name.equalsIgnoreCase(ATTR_CA_CERT)) {
            mCACert = (byte[]) obj;
        } else if (name.equalsIgnoreCase(ATTR_CRL_CACHE)) {
            mCRLCache = (Hashtable<BigInteger, RevokedCertificate>) obj;
        } else if (name.equalsIgnoreCase(ATTR_REVOKED_CERTS)) {
            mRevokedCerts = (Hashtable<BigInteger, RevokedCertificate>) obj;
        } else if (name.equalsIgnoreCase(ATTR_UNREVOKED_CERTS)) {
            mUnrevokedCerts = (Hashtable<BigInteger, RevokedCertificate>) obj;
        } else if (name.equalsIgnoreCase(ATTR_EXPIRED_CERTS)) {
            mExpiredCerts = (Hashtable<BigInteger, RevokedCertificate>) obj;
        } else if (name.equalsIgnoreCase(ATTR_DELTA_CRL)) {
            mDeltaCRL = (byte[]) obj;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    @Override
    public Object get(String name) throws EBaseException {
        if (name.equalsIgnoreCase(ATTR_ID)) {
            return mId;
        } else if (name.equalsIgnoreCase(ATTR_CRL_NUMBER)) {
            return mCRLNumber;
        } else if (name.equalsIgnoreCase(ATTR_CRL_SIZE)) {
            return mCRLSize;
        } else if (name.equalsIgnoreCase(ATTR_THIS_UPDATE)) {
            return mThisUpdate;
        } else if (name.equalsIgnoreCase(ATTR_NEXT_UPDATE)) {
            return mNextUpdate;
        } else if (name.equalsIgnoreCase(ATTR_DELTA_NUMBER)) {
            return mDeltaCRLNumber;
        } else if (name.equalsIgnoreCase(ATTR_DELTA_SIZE)) {
            return mDeltaCRLSize;
        } else if (name.equalsIgnoreCase(ATTR_FIRST_UNSAVED)) {
            return mFirstUnsaved;
        } else if (name.equalsIgnoreCase(ATTR_CRL)) {
            return mCRL;
        } else if (name.equalsIgnoreCase(ATTR_CA_CERT)) {
            return mCACert;
        } else if (name.equalsIgnoreCase(ATTR_CRL_CACHE)) {
            return mCRLCache;
        } else if (name.equalsIgnoreCase(ATTR_REVOKED_CERTS)) {
            return mRevokedCerts;
        } else if (name.equalsIgnoreCase(ATTR_UNREVOKED_CERTS)) {
            return mUnrevokedCerts;
        } else if (name.equalsIgnoreCase(ATTR_EXPIRED_CERTS)) {
            return mExpiredCerts;
        } else if (name.equalsIgnoreCase(ATTR_DELTA_CRL)) {
            return mDeltaCRL;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

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
     * Retrieve unique CRL identifier.
     *
     * @return unique CRL identifier
     */
    public String getId() {
        return mId;
    }

    /**
     * Retrieves current CRL number out of CRL issuing point record.
     *
     * @return current CRL number
     */
    public BigInteger getCRLNumber() {
        return mCRLNumber;
    }

    /**
     * Retrieves CRL size measured by the number of entries.
     *
     * @return CRL size
     */
    public Long getCRLSize() {
        return mCRLSize;
    }

    /**
     * Retrieves this update time.
     *
     * @return time of this update
     */
    public Date getThisUpdate() {
        return mThisUpdate;
    }

    /**
     * Retrieves next update time.
     *
     * @return time of next update
     */
    public Date getNextUpdate() {
        return mNextUpdate;
    }

    /**
     * Retrieves current delta CRL number out of CRL issuing point record.
     *
     * @return current delta CRL number
     */
    public BigInteger getDeltaCRLNumber() {
        return mDeltaCRLNumber;
    }

    /**
     * Retrieves delta CRL size measured by the number of entries.
     *
     * @return delta CRL size
     */
    public Long getDeltaCRLSize() {
        return mDeltaCRLSize;
    }

    /**
     * Retrieve Retrieve reference to the first unsaved data.
     *
     * @return reference to the first unsaved data
     */
    public String getFirstUnsaved() {
        return mFirstUnsaved;
    }

    /**
     * Retrieves encoded CRL.
     *
     * @return encoded CRL
     */
    public byte[] getCRL() {
        return mCRL;
    }

    /**
     * Retrieves encoded delta CRL.
     *
     * @return encoded delta CRL
     */
    public byte[] getDeltaCRL() {
        return mDeltaCRL;
    }

    /**
     * Retrieves encoded CA certificate.
     *
     * @return encoded CA certificate
     */
    public byte[] getCACert() {
        return mCACert;
    }

    /**
     * Retrieves cache information about CRL.
     *
     * @return list of recently revoked certificates
     */
    public Hashtable<BigInteger, RevokedCertificate> getCRLCacheNoClone() {
        return mCRLCache == null ? null : mCRLCache;
    }

    @SuppressWarnings("unchecked")
    public Hashtable<BigInteger, RevokedCertificate> getCRLCache() {
        return mCRLCache == null ? null : (Hashtable<BigInteger, RevokedCertificate>) mCRLCache.clone();
    }

    /**
     * Retrieves cache information about revoked certificates.
     *
     * @return list of recently revoked certificates
     */
    @SuppressWarnings("unchecked")
    public Hashtable<BigInteger, RevokedCertificate> getRevokedCerts() {
        return mRevokedCerts == null ? null : (Hashtable<BigInteger, RevokedCertificate>) mRevokedCerts.clone();
    }

    /**
     * Retrieves cache information about certificates released from hold.
     *
     * @return list of certificates recently released from hold
     */
    @SuppressWarnings("unchecked")
    public Hashtable<BigInteger, RevokedCertificate> getUnrevokedCerts() {
        return mUnrevokedCerts == null ? null : (Hashtable<BigInteger, RevokedCertificate>) mUnrevokedCerts.clone();
    }

    /**
     * Retrieves cache information about expired certificates.
     *
     * @return list of recently expired certificates
     */
    @SuppressWarnings("unchecked")
    public Hashtable<BigInteger, RevokedCertificate> getExpiredCerts() {
        return mExpiredCerts == null ? null : (Hashtable<BigInteger, RevokedCertificate>) mExpiredCerts.clone();
    }
}

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

import netscape.security.x509.RevokedCertificate;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;

/**
 * A class represents a CRL issuing point record.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CRLIssuingPointRecord implements ICRLIssuingPointRecord, IDBObj {

    /**
     *
     */
    private static final long serialVersionUID = 400565044343905267L;
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
    protected static Vector<String> mNames = new Vector<String>();
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
     * Retrieve unique CRL identifier.
     */
    public String getId() {
        return mId;
    }

    /**
     * Retrieves CRL number.
     */
    public BigInteger getCRLNumber() {
        return mCRLNumber;
    }

    /**
     * Retrieves CRL size.
     */
    public Long getCRLSize() {
        return mCRLSize;
    }

    /**
     * Retrieves this update time.
     */
    public Date getThisUpdate() {
        return mThisUpdate;
    }

    /**
     * Retrieves next update time.
     */
    public Date getNextUpdate() {
        return mNextUpdate;
    }

    /**
     * Retrieves delta CRL number.
     */
    public BigInteger getDeltaCRLNumber() {
        return mDeltaCRLNumber;
    }

    /**
     * Retrieves CRL size.
     */
    public Long getDeltaCRLSize() {
        return mDeltaCRLSize;
    }

    /**
     * Retrieve unique CRL identifier.
     */
    public String getFirstUnsaved() {
        return mFirstUnsaved;
    }

    /**
     * Retrieves CRL encodings.
     */
    public byte[] getCRL() {
        return mCRL;
    }

    /**
     * Retrieves CRL encodings.
     */
    public byte[] getDeltaCRL() {
        return mDeltaCRL;
    }

    public byte[] getCACert() {
        return mCACert;
    }

    public Hashtable<BigInteger, RevokedCertificate> getCRLCacheNoClone() {
        if (mCRLCache == null)
            return null;
        else
            return mCRLCache;
    }

    @SuppressWarnings("unchecked")
    public Hashtable<BigInteger, RevokedCertificate> getCRLCache() {
        if (mCRLCache == null)
            return null;
        else
            return (Hashtable<BigInteger, RevokedCertificate>) mCRLCache.clone();
    }

    /**
     * Retrieves cache info of revoked certificates.
     */
    @SuppressWarnings("unchecked")
    public Hashtable<BigInteger, RevokedCertificate> getRevokedCerts() {
        if (mRevokedCerts == null)
            return null;
        else
            return (Hashtable<BigInteger, RevokedCertificate>) mRevokedCerts.clone();
    }

    /**
     * Retrieves cache info of unrevoked certificates.
     */
    @SuppressWarnings("unchecked")
    public Hashtable<BigInteger, RevokedCertificate> getUnrevokedCerts() {
        if (mUnrevokedCerts == null)
            return null;
        else
            return (Hashtable<BigInteger, RevokedCertificate>) mUnrevokedCerts.clone();
    }

    /**
     * Retrieves cache info of expired certificates.
     */
    @SuppressWarnings("unchecked")
    public Hashtable<BigInteger, RevokedCertificate> getExpiredCerts() {
        if (mExpiredCerts == null)
            return null;
        else
            return (Hashtable<BigInteger, RevokedCertificate>) mExpiredCerts.clone();
    }
}

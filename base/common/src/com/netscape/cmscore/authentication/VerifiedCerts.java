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
package com.netscape.cmscore.authentication;

import java.math.BigInteger;

import netscape.security.x509.X509CertImpl;

/**
 * class storing verified certificates.
 *
 * @version $Revision$, $Date$
 */

public class VerifiedCerts {

    /* the value type of the dn component */
    private int mFirst = 0;
    private int mLast = 0;
    private int mNext = 0;
    private VerifiedCert[] mVCerts = null;
    private long mInterval = 0;
    private long mUnknownStateInterval = 0;

    /**
     * Constructs verified certiificates list
     */

    public VerifiedCerts(int size, long interval) {
        mVCerts = new VerifiedCert[size];
        mInterval = interval;
        mUnknownStateInterval = interval;
    }

    public VerifiedCerts(int size, long interval, long unknownStateInterval) {
        mVCerts = new VerifiedCert[size];
        mInterval = interval;
        mUnknownStateInterval = unknownStateInterval;
    }

    public synchronized void update(X509CertImpl cert, int status) {
        if (cert != null) {
            byte[] certEncoded = null;

            try {
                certEncoded = cert.getEncoded();
            } catch (Exception e) {
            }
            if ((certEncoded != null ||
                    (status == VerifiedCert.CHECKED && mUnknownStateInterval > 0))
                    && mInterval > 0) {
                update(cert.getSerialNumber(), certEncoded, status);
            }
        }
    }

    public synchronized void update(BigInteger serialNumber, byte[] certEncoded, int status) {
        if ((status == VerifiedCert.NOT_REVOKED ||
                status == VerifiedCert.REVOKED ||
                (status == VerifiedCert.CHECKED && mUnknownStateInterval > 0))
                && mInterval > 0) {
            if (mLast == mNext && mFirst == mNext) { // empty
                mVCerts[mNext] = new VerifiedCert(serialNumber, certEncoded, status);
                mNext = next(mNext);
            } else if (mFirst == mNext) { // full
                mFirst = next(mFirst);
                mVCerts[mNext] = new VerifiedCert(serialNumber, certEncoded, status);
                mLast = mNext;
                mNext = next(mNext);
            } else {
                mVCerts[mNext] = new VerifiedCert(serialNumber, certEncoded, status);
                mLast = mNext;
                mNext = next(mNext);
            }
        }
    }

    public synchronized int check(X509CertImpl cert) {
        int status = VerifiedCert.UNKNOWN;

        if (mLast != mNext && mInterval > 0) { // if not empty and
            if (cert != null) {
                byte[] certEncoded = null;

                try {
                    certEncoded = cert.getEncoded();
                } catch (Exception e) {
                }
                if (certEncoded != null) {
                    status = check(cert.getSerialNumber(), certEncoded);
                }
            }
        }

        return status;
    }

    public synchronized int check(BigInteger serialNumber, byte[] certEncoded) {
        int status = VerifiedCert.UNKNOWN;
        int i = mLast;

        if (mVCerts != null && mLast != mNext && mInterval > 0) { // if not empty and
            while (status == VerifiedCert.UNKNOWN) {
                if (mVCerts[i] == null)
                    return status;
                status = mVCerts[i].check(serialNumber, certEncoded,
                            mInterval, mUnknownStateInterval);
                if (status == VerifiedCert.EXPIRED) {
                    if (mFirst == mLast)
                        mNext = mLast;
                    else
                        mFirst = next(i);
                    break;
                } else if (mFirst == i) {
                    break;
                } else {
                    i = previous(i);
                }
            }
            if (status == VerifiedCert.UNKNOWN)
                status = mVCerts[i].check(serialNumber, certEncoded,
                            mInterval, mUnknownStateInterval);
        }

        return status;
    }

    private int next(int i) {
        i++;
        if (i >= mVCerts.length)
            i = 0;

        return i;
    }

    private int previous(int i) {
        if (i <= 0)
            i = mVCerts.length;
        i--;

        return i;
    }
}

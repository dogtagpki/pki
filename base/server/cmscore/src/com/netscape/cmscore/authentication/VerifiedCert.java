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
import java.util.Date;

import com.netscape.certsrv.apps.CMS;

/**
 * class storing verified certificate.
 *
 * @version $Revision$, $Date$
 */

public class VerifiedCert {
    public static final int CHECKED = 4;
    public static final int EXPIRED = 3;
    public static final int NOT_REVOKED = 2;
    public static final int REVOKED = 1;
    public static final int UNKNOWN = 0;

    private int mStatus = UNKNOWN;
    private Date mCreated = null;
    private BigInteger mSerialNumber = null;
    private byte[] mCertEncoded = null;

    /**
     * Constructs verified certiificate record
     */

    public VerifiedCert(BigInteger serialNumber, byte[] certEncoded,
            int status) {
        mStatus = status;
        mSerialNumber = serialNumber;
        mCertEncoded = certEncoded;
        mCreated = CMS.getCurrentDate();
    }

    public int check(BigInteger serialNumber, byte[] certEncoded,
            long interval, long unknownStateInterval) {
        int status = UNKNOWN;

        if (mSerialNumber.equals(serialNumber)) {
            if (mCertEncoded != null) {
                if (certEncoded != null &&
                        mCertEncoded.length == certEncoded.length) {
                    int i;

                    for (i = 0; i < mCertEncoded.length; i++) {
                        if (mCertEncoded[i] != certEncoded[i])
                            break;
                    }
                    if (i >= mCertEncoded.length) {
                        Date expires = new Date(mCreated.getTime() + (interval * 1000));
                        Date now = CMS.getCurrentDate();

                        if (now.after(expires))
                            mStatus = EXPIRED;
                        status = mStatus;
                    }
                }
            } else if (unknownStateInterval > 0) {
                Date expires = new Date(mCreated.getTime() + (unknownStateInterval * 1000));
                Date now = CMS.getCurrentDate();

                if (now.after(expires))
                    mStatus = EXPIRED;
                status = mStatus; // CHECKED
            }
        }

        return status;
    }
}

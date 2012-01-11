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
package com.netscape.ca;

import java.math.BigInteger;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.dbs.CertRecord;

/**
 * A CRL Issuing point that contains revoked certs, include onces that
 * have expired.
 */
public class CRLWithExpiredCerts extends CRLIssuingPoint {

    /**
     * overrides getRevokedCerts in CRLIssuingPoint to include
     * all revoked certs, including once that have expired.
     * 
     * @param thisUpdate parameter is ignored.
     * 
     * @exception EBaseException if an exception occured getting revoked
     *                certificates from the database.
     */
    public String getFilter() {
        // PLEASE DONT CHANGE THE FILTER. It is indexed.
        // Changing it will degrade performance. See
        // also com.netscape.certsetup.LDAPUtil.java
        String filter =
                "(|(" + CertRecord.ATTR_CERT_STATUS + "=" +
                        CertRecord.STATUS_REVOKED + ")" +
                        "(" + CertRecord.ATTR_CERT_STATUS + "=" +
                        CertRecord.STATUS_REVOKED_EXPIRED + "))";

        // check if any ranges specified.
        if (mBeginSerial != null)
            filter += "(" + CertRecord.ATTR_ID + ">=" + mBeginSerial.toString() + ")";
        if (mEndSerial != null)
            filter += "(" + CertRecord.ATTR_ID + "<=" + mEndSerial.toString() + ")";
        // get all revoked non-expired certs.
        if (mEndSerial != null || mBeginSerial != null) {
            filter = "(&" + filter + ")";
        }
        return filter;
    }

    /**
     * registers expired certificates
     */
    public void addExpiredCert(BigInteger serialNumber) {
        // don't do anything
    }
}

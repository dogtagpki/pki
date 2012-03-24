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
package netscape.security.x509;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;

/**
 * <p>
 * Abstract class for a revoked certificate in a CRL (Certificate Revocation List).
 * 
 * The ASN.1 definition for <em>revokedCertificates</em> is:
 * 
 * <pre>
 *  revokedCertificates    SEQUENCE OF SEQUENCE  {
 *      userCertificate    CertificateSerialNumber,
 *      revocationDate     ChoiceOfTime,
 *      crlEntryExtensions Extensions OPTIONAL
 *                         -- if present, must be v2
 *  }  OPTIONAL
 * <p>
 *  CertificateSerialNumber  ::=  INTEGER
 * <p>
 *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 * <p>
 *  Extension  ::=  SEQUENCE  {
 *      extnId        OBJECT IDENTIFIER,
 *      critical      BOOLEAN DEFAULT FALSE,
 *      extnValue     OCTET STRING
 *                    -- contains a DER encoding of a value
 *                    -- of the type registered for use with
 *                    -- the extnId object identifier value
 *  }
 * </pre>
 * 
 * @see X509CRL
 * 
 * @author Hemma Prafullchandra
 * @version 1.4 97/12/10
 */

public abstract class RevokedCertificate extends X509CRLEntry {
    /* implements X509Extension { */

    /**
     * Gets the serial number for this RevokedCertificate,
     * the <em>userCertificate</em>.
     * 
     * @return the serial number.
     */
    public abstract BigInteger getSerialNumber();

    /**
     * Gets the revocation date for this RevokedCertificate,
     * the <em>revocationDate</em>.
     * 
     * @return the revocation date.
     */
    public abstract Date getRevocationDate();

    /**
     * Returns true if this revoked certificate entry has
     * extensions.
     * 
     * @return true if this entry has extensions, false otherwise.
     */
    public abstract boolean hasExtensions();

    /**
     * Returns a string representation of this revoked certificate.
     * 
     * @return a string representation of this revoked certificate.
     */
    public abstract String toString();

    public abstract CRLExtensions getExtensions();

}

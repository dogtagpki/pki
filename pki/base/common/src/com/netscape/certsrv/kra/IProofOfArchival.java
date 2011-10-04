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
package com.netscape.certsrv.kra;


import java.io.*;
import java.math.*;
import java.util.*;
import java.security.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;


/**
 * An interface represents a proof of archival.
 * <P>
 * Here is the ASN1 definition of a proof of escrow:
 * <PRE>
 * ProofOfArchival ::= SIGNED {
 *   SEQUENCE {
 *     version [0] Version DEFAULT v1,
 *     serialNumber INTEGER,
 *     subjectName Name,
 *     issuerName Name,
 *     dateOfArchival Time,
 *     extensions [1] Extensions OPTIONAL
 *   }
 * }
 * </PRE>
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IProofOfArchival {

    /**
     * Retrieves version of this proof.
     *
     * @return version
     */
    public BigInteger getVersion();

    /**
     * Retrieves the serial number.
     *
     * @return serial number
     */
    public BigInteger getSerialNumber();

    /**
     * Retrieves the subject name.
     *
     * @return subject name
     */
    public String getSubjectName();

    /**
     * Retrieves the issuer name.
     *
     * @return issuer name
     */
    public String getIssuerName();

    /**
     * Returns the beginning of the escrowed perioid.
     *
     * @return date of archival
     */
    public Date getDateOfArchival();
}

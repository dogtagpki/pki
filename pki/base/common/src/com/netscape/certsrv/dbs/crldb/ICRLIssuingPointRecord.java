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
package com.netscape.certsrv.dbs.crldb;


import java.util.*;
import java.math.*;
import java.io.*;
import java.security.cert.*;
import netscape.ldap.*;
import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.*;


/**
 * An interface that defines abilities of
 * a CRL issuing point record.
 *
 * @version $Revision$, $Date$
 */
public interface ICRLIssuingPointRecord extends IDBObj {

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
    public static final String ATTR_DELTA_CRL = "deltaCRL";

    public static final String CLEAN_CACHE = "-1";
    public static final String NEW_CACHE   = "-2";

    /**
     * Retrieve unique CRL identifier.
     *
     * @return unique CRL identifier
     */
    public String getId();

    /**
     * Retrieves current CRL number out of CRL issuing point record.
     *
     * @return current CRL number
     */
    public BigInteger getCRLNumber();

    /**
     * Retrieves CRL size measured by the number of entries.
     *
     * @return CRL size
     */
    public Long getCRLSize();

    /**
     * Retrieves this update time.
     *
     * @return time of this update
     */
    public Date getThisUpdate();

    /**
     * Retrieves next update time.
     *
     * @return time of next update
     */
    public Date getNextUpdate();

    /**
     * Retrieves current delta CRL number out of CRL issuing point record.
     *
     * @return current delta CRL number
     */
    public BigInteger getDeltaCRLNumber();

    /**
     * Retrieves delta CRL size measured by the number of entries.
     *
     * @return delta CRL size
     */
    public Long getDeltaCRLSize();

    /**
     * Retrieve Retrieve reference to the first unsaved data.
     *
     * @return reference to the first unsaved data
     */
    public String getFirstUnsaved();

    /**
     * Retrieves encoded CRL.
     *
     * @return encoded CRL
     */
    public byte[] getCRL();

    /**
     * Retrieves encoded delta CRL.
     *
     * @return encoded delta CRL
     */
    public byte[] getDeltaCRL();

    /**
     * Retrieves encoded CA certificate.
     *
     * @return encoded CA certificate
     */
    public byte[] getCACert();

    /**
     * Retrieves cache information about CRL.
     *
     * @return list of recently revoked certificates
     */
    public Hashtable getCRLCacheNoClone();
    public Hashtable getCRLCache();

    /**
     * Retrieves cache information about revoked certificates.
     *
     * @return list of recently revoked certificates
     */
    public Hashtable getRevokedCerts();

    /**
     * Retrieves cache information about certificates released from hold.
     *
     * @return list of certificates recently released from hold
     */
    public Hashtable getUnrevokedCerts();

    /**
     * Retrieves cache information about expired certificates.
     *
     * @return list of recently expired certificates
     */
    public Hashtable getExpiredCerts();
}

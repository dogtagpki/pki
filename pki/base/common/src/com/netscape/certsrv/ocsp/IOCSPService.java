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
package com.netscape.certsrv.ocsp;


import java.util.*;
import java.security.*;
import java.util.Vector;
import java.io.*;
import java.io.InputStream;
import java.io.IOException;

import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.asn1.BIT_STRING;

import netscape.security.x509.*;

import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.logging.*;

import com.netscape.cmsutil.ocsp.*;


/**
 * This class represents the servlet that serves the Online Certificate
 * Status Protocol (OCSP) requests.
 *
 * @version $Revision: 14561 $ $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IOCSPService
{
    /**
     * This method validates the information associated with the specified
     * OCSP request and returns an OCSP response.
     * <P>
     *
     * @param r an OCSP request
     * @return OCSPResponse the OCSP response associated with the specified
     *     OCSP request
     * @exception EBaseException an error associated with the inability to
     *     process the supplied OCSP request
     */
    public OCSPResponse validate(OCSPRequest r) 
        throws EBaseException;

    /**
     * Returns the in-memory count of the processed OCSP requests.
     *
     * @return number of processed OCSP requests in memory
     */
    public long getNumOCSPRequest();

    /**
     * Returns the in-memory time (in mini-second) of
     * the processed time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPRequestTotalTime();

    /**
     * Returns the in-memory time (in mini-second) of
     * the signing time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalSignTime();

    public long getOCSPTotalLookupTime();

    /**
     * Returns the total data signed
     * for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalData();
}


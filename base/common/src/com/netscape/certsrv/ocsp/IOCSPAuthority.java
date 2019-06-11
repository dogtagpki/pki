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

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.security.ISigningUnit;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.ResponderID;
import com.netscape.cmsutil.ocsp.ResponseData;

import org.mozilla.jss.netscape.security.x509.X500Name;

/**
 * This class represents the primary interface for the Online Certificate
 * Status Protocol (OCSP) server.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface IOCSPAuthority extends ISubsystem {
    public static final String ID = "ocsp";

    public final static OBJECT_IDENTIFIER OCSP_NONCE = new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.48.1.2");

    public final static String PROP_DEF_STORE_ID = "storeId";
    public final static String PROP_STORE = "store";
    public final static String PROP_SIGNING_SUBSTORE = "signing";
    public static final String PROP_NICKNAME = "certNickname";
    public final static String PROP_NEW_NICKNAME = "newNickname";

    /**
     * This method retrieves the OCSP store given its name.
     * <P>
     *
     * @param id the string representation of an OCSP store
     * @return IOCSPStore an instance of an OCSP store object
     */
    public IOCSPStore getOCSPStore(String id);

    /**
     * This method retrieves the signing unit.
     * <P>
     *
     * @return ISigningUnit an instance of a signing unit object
     */
    public ISigningUnit getSigningUnit();

    /**
     * This method retrieves the responder ID by its name.
     * <P>
     *
     * @return ResponderID an instance of a responder ID
     */
    public ResponderID getResponderIDByName();

    /**
     * This method retrieves the responder ID by its hash.
     * <P>
     *
     * @return ResponderID an instance of a responder ID
     */
    public ResponderID getResponderIDByHash();

    /**
     * This method retrieves the default OCSP store
     * (i. e. - information from the internal database).
     * <P>
     *
     * @return IDefStore an instance of the default OCSP store
     */
    public IDefStore getDefaultStore();

    /**
     * This method sets the supplied algorithm as the default signing algorithm.
     * <P>
     *
     * @param algorithm a string representing the requested algorithm
     * @exception EBaseException if the algorithm is unknown or disallowed
     */
    public void setDefaultAlgorithm(String algorithm)
            throws EBaseException;

    /**
     * This method retrieves the default signing algorithm.
     * <P>
     *
     * @return String the name of the default signing algorithm
     */
    public String getDefaultAlgorithm();

    /**
     * This method retrieves all potential OCSP signing algorithms.
     * <P>
     *
     * @return String[] the names of all potential OCSP signing algorithms
     */
    public String[] getOCSPSigningAlgorithms();

    /**
     * This method logs the specified message at the specified level.
     * <P>
     *
     * @param level the log level
     * @param msg the log message
     */
    public void log(int level, String msg);

    /**
     * This method logs the specified message at the specified level given
     * the specified event.
     * <P>
     *
     * @param level the log message
     * @param msg the log message
     */
    public void audit(int level, String msg);

    /**
     * This method retrieves the X500Name of an OCSP server instance.
     * <P>
     *
     * @return X500Name an instance of the X500 name object
     */
    public X500Name getName();

    /**
     * This method signs the basic OCSP response data provided as a parameter.
     * <P>
     *
     * @param rd response data
     * @return BasicOCSPResponse signed response data
     * @exception EBaseException error associated with an inability to sign
     *                the specified response data
     */
    public BasicOCSPResponse sign(ResponseData rd)
            throws EBaseException;

    public void incTotalTime(long inc);

    public void incSignTime(long inc);

    public void incLookupTime(long inc);

    public void incNumOCSPRequest(long inc);
}

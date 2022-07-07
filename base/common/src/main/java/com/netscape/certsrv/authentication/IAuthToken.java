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
package com.netscape.certsrv.authentication;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.usrgrp.Certificates;

/**
 * AuthToken interface.
 */
public interface IAuthToken {

    /**
     * Constant for userid.
     */
    public static final String USER = "user";
    public static final String USER_DN = "userdn";
    public static final String USER_ID = "userid";
    public static final String UID = "uid";
    public static final String GROUP = "group";
    public static final String GROUPS = "groups";

    /* Subject name of the certificate request in the authenticating entry */
    public static final String TOKEN_CERT_SUBJECT = "tokenCertSubject";

    /* Subject name of the authenticated cert */
    public static final String TOKEN_AUTHENTICATED_CERT_SUBJECT = "tokenAuthenticatedCertSubject";
    /* Subject DN of the Shared Token authenticated entry */
    public static final String TOKEN_SHARED_TOKEN_AUTHENTICATED_CERT_SUBJECT = "tokenSharedTokenAuthenticatedCertSubject";

    /* NotBefore value of the certificate in the authenticating entry */
    public static final String TOKEN_CERT_NOTBEFORE = "tokenCertNotBefore";

    /* NotAfter value of the certificate in the authenticating entry */
    public static final String TOKEN_CERT_NOTAFTER = "tokenCertNotAfter";

    /* Cert Extentions value of the certificate in the authenticating entry */
    public static final String TOKEN_CERT_EXTENSIONS = "tokenCertExts";

    /* Serial number of the certificate in the authenticating entry */
    public static final String TOKEN_CERT_SERIALNUM = "certSerial";

    /**
     * Certificate to be renewed
     */
    public static final String TOKEN_CERT = "tokenCert";

    /* Certificate to be revoked */
    public static final String TOKEN_CERT_TO_REVOKE = "tokenCertToRevoke";

    /**
     * Name of the authentication manager that created the AuthToken
     * as a string.
     */
    public static final String TOKEN_AUTHMGR_INST_NAME = "authMgrInstName";

    /**
     * Time of authentication as a java.util.Date
     */
    public static final String TOKEN_AUTHTIME = "authTime";

    /**
     * Gets an attribute value.
     *
     * @param name the name of the attribute to return.
     * @exception EBaseException on attribute handling errors.
     * @return the attribute value
     */
    public Object get(String name);

    /**
     * Gets an attribute value.
     *
     * @param name the name of the attribute to return.
     * @exception EBaseException on attribute handling errors.
     * @return the attribute value
     */
    public String getInString(String name);

    /**
     * Returns an enumeration of the names of the attributes existing within
     * this AttrSet.
     *
     * @return an enumeration of the attribute names.
     */
    public Enumeration<String> getElements();

    /************
     * Helpers for non-string sets and gets.
     * These are needed because AuthToken is stored in Request (which can
     * only store string values
     */

    /**
     * Retrieves the byte array value for name. The value should have been
     * previously stored as a byte array (it will be CMS.AtoB decoded).
     *
     * @param name The attribute name.
     * @return The byte array or null on error.
     */
    public byte[] getInByteArray(String name);

    /**
     * Retrieves the Integer value for name.
     *
     * @param name The attribute name.
     * @return The Integer or null on error.
     */
    public Integer getInInteger(String name);

    /**
     * Retrieves the BigInteger array value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public BigInteger[] getInBigIntegerArray(String name);

    /**
     * Retrieves the Date value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public Date getInDate(String name);

    /**
     * Retrieves the String array value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public String[] getInStringArray(String name);

    /**
     * Retrieves the X509CertImpl value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public X509CertImpl getInCert(String name);

    /**
     * Retrieves the CertificateExtensions value for name.
     *
     * @param name The attribute name.
     * @return The value.
     * @throws IOException
     */
    public CertificateExtensions getInCertExts(String name) throws IOException;

    /**
     * Retrieves the Certificates value for name.
     *
     * @param name The attribute name.
     * @return The value.
     * @throws IOException
     * @throws CertificateException
     */
    public Certificates getInCertificates(String name) throws IOException, CertificateException;

    /**
     * Retrieves the byte[][] value for name.
     *
     * @param name The attribute name.
     * @return The value.
     * @throws IOException
     */
    public byte[][] getInByteArrayArray(String name) throws IOException;
}

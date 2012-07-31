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

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.usrgrp.Certificates;

/**
 * AuthToken interface.
 */
public interface IAuthToken {

    /**
     * Constant for userid.
     */
    public static final String USER_ID = "userid";

    /**
     * Sets an attribute value within this AttrSet.
     *
     * @param name the name of the attribute
     * @param value the attribute object.
     * @return false on an error
     */
    public boolean set(String name, String value);

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
     * These are needed because AuthToken is stored in IRequest (which can
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
     * Stores the byte array with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on an error
     */
    public boolean set(String name, byte[] value);

    /**
     * Retrieves the Integer value for name.
     *
     * @param name The attribute name.
     * @return The Integer or null on error.
     */
    public Integer getInInteger(String name);

    /**
     * Stores the Integer with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on an error
     */
    public boolean set(String name, Integer value);

    /**
     * Retrieves the BigInteger array value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public BigInteger[] getInBigIntegerArray(String name);

    /**
     * Stores the BigInteger array with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on an error
     */
    public boolean set(String name, BigInteger[] value);

    /**
     * Retrieves the Date value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public Date getInDate(String name);

    /**
     * Stores the Date with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on an error
     */
    public boolean set(String name, Date value);

    /**
     * Retrieves the String array value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public String[] getInStringArray(String name);

    /**
     * Stores the String array with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return False on error.
     */
    public boolean set(String name, String[] value);

    /**
     * Retrieves the X509CertImpl value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public X509CertImpl getInCert(String name);

    /**
     * Stores the X509CertImpl with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on error
     */
    public boolean set(String name, X509CertImpl value);

    /**
     * Retrieves the CertificateExtensions value for name.
     *
     * @param name The attribute name.
     * @return The value.
     * @throws IOException
     */
    public CertificateExtensions getInCertExts(String name) throws IOException;

    /**
     * Stores the CertificateExtensions with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on error
     */
    public boolean set(String name, CertificateExtensions value);

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
     * Stores the Certificates with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on error
     */
    public boolean set(String name, Certificates value);

    /**
     * Retrieves the byte[][] value for name.
     *
     * @param name The attribute name.
     * @return The value.
     * @throws IOException
     */
    public byte[][] getInByteArrayArray(String name) throws IOException;

    /**
     * Stores the byte[][] with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on error
     */
    public boolean set(String name, byte[][] value);
}

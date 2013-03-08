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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.usrgrp.Certificates;

/**
 * Authentication token returned by Authentication Managers.
 * Upon return, it contains authentication/identification information
 * as well as information retrieved from the database where the
 * authentication was done against. Each authentication manager has
 * its own list of such information. See individual authenticaiton
 * manager for more details.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class AuthToken implements IAuthToken {
    protected Hashtable<String, Object> mAttrs = null;

    /* Subject name of the certificate in the authenticating entry */
    public static final String TOKEN_CERT_SUBJECT = "tokenCertSubject";

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
     * Plugin name of the authentication manager that created the
     * AuthToken as a string.
     */
    public static final String TOKEN_AUTHMGR_IMPL_NAME = "authMgrImplName";

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
     * Constructs an instance of a authentication token.
     * The token by default contains the following attributes: <br>
     *
     * <pre>
     * 	"authMgrInstName" - The authentication manager instance name.
     * 	"authMgrImplName" - The authentication manager plugin name.
     * 	"authTime" - The - The time of authentication.
     * </pre>
     *
     * @param authMgr The authentication manager that created this Token.
     */
    public AuthToken(IAuthManager authMgr) {
        mAttrs = new Hashtable<String, Object>();
        if (authMgr != null) {
            set(TOKEN_AUTHMGR_INST_NAME, authMgr.getName());
            set(TOKEN_AUTHMGR_IMPL_NAME, authMgr.getImplName());
        }
        set(TOKEN_AUTHTIME, new Date());
    }

    public Object get(String attrName) {
        return mAttrs.get(attrName);
    }

    public String getInString(String attrName) {
        return (String) mAttrs.get(attrName);
    }

    public boolean set(String attrName, String value) {
        if (value == null) {
            return false;
        }
        mAttrs.put(attrName, value);
        return true;
    }

    /**
     * Removes an attribute in the AuthToken
     *
     * @param attrName The name of the attribute to remove.
     */
    public void delete(String attrName) {
        mAttrs.remove(attrName);
    }

    /**
     * Enumerate all attribute names in the AuthToken.
     *
     * @return Enumeration of all attribute names in this AuthToken.
     */
    public Enumeration<String> getElements() {
        return (mAttrs.keys());
    }

    public byte[] getInByteArray(String name) {
        String value = getInString(name);
        if (value == null) {
            return null;
        }
        return CMS.AtoB(value);
    }

    public boolean set(String name, byte[] value) {
        if (value == null) {
            return false;
        }
        return set(name, CMS.BtoA(value));
    }

    public Integer getInInteger(String name) {
        String strVal = getInString(name);
        if (strVal == null) {
            return null;
        }
        try {
            return Integer.valueOf(strVal);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public boolean set(String name, Integer value) {
        if (value == null) {
            return false;
        }
        return set(name, value.toString());
    }

    public BigInteger[] getInBigIntegerArray(String name) {
        String value = getInString(name);
        if (value == null) {
            return null;
        }
        String[] values = value.split(",");
        if (values.length == 0) {
            return null;
        }
        BigInteger[] result = new BigInteger[values.length];
        for (int i = 0; i < values.length; i++) {
            try {
                result[i] = new BigInteger(values[i]);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return result;
    }

    public boolean set(String name, BigInteger[] value) {
        if (value == null) {
            return false;
        }
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < value.length; i++) {
            if (i != 0) {
                buffer.append(",");
            }
            buffer.append(value[i].toString());
        }
        return set(name, buffer.toString());
    }

    public Date getInDate(String name) {
        String value = getInString(name);
        if (value == null) {
            return null;
        }
        try {
            return new Date(Long.parseLong(value));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public boolean set(String name, Date value) {
        if (value == null) {
            return false;
        }
        return set(name, String.valueOf(value.getTime()));
    }

    public String[] getInStringArray(String name) {
        String[] stringValues;

        byte[] byteValue = getInByteArray(name);
        if (byteValue == null) {
            return null;
        }
        try {
            DerInputStream in = new DerInputStream(byteValue);
            DerValue[] derValues = in.getSequence(5);
            stringValues = new String[derValues.length];
            for (int i = 0; i < derValues.length; i++) {
                stringValues[i] = derValues[i].getAsString();
            }
        } catch (IOException e) {
            return null;
        }
        return stringValues;
    }

    public boolean set(String name, String[] value) {
        if (value == null) {
            return false;
        }

        DerValue[] derValues = new DerValue[value.length];
        try (DerOutputStream out = new DerOutputStream()) {
            for (int i = 0; i < value.length; i++) {
                derValues[i] = new DerValue(value[i]);
            }
            out.putSequence(derValues);
            return set(name, out.toByteArray());
        } catch (IOException e) {
            return false;
        }
    }

    public X509CertImpl getInCert(String name) {
        byte[] data = getInByteArray(name);
        if (data == null) {
            return null;
        }
        try {
            return new X509CertImpl(data);
        } catch (CertificateException e) {
            return null;
        }
    }

    public boolean set(String name, X509CertImpl value) {
        if (value == null) {
            return false;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            value.encode(out);
        } catch (CertificateEncodingException e) {
            return false;
        }
        return set(name, out.toByteArray());
    }

    public CertificateExtensions getInCertExts(String name) throws IOException {
        CertificateExtensions exts = null;
        byte[] data = getInByteArray(name);
        if (data != null) {
            exts = new CertificateExtensions();
            // exts.decode() doesn't work for empty CertExts
            exts.decodeEx(new ByteArrayInputStream(data));
        }
        return exts;
    }

    public boolean set(String name, CertificateExtensions value) {
        if (value == null) {
            return false;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            value.encode(out);
        } catch (IOException e) {
            return false;
        } catch (CertificateException e) {
            return false;
        }
        return set(name, out.toByteArray());
    }

    public Certificates getInCertificates(String name) throws IOException, CertificateException {
        X509CertImpl[] certArray;

        byte[] byteValue = getInByteArray(name);
        if (byteValue == null) {
            return null;
        }

        DerInputStream in = new DerInputStream(byteValue);
        DerValue[] derValues = in.getSequence(5);
        certArray = new X509CertImpl[derValues.length];
        for (int i = 0; i < derValues.length; i++) {
            byte[] certData = derValues[i].toByteArray();
            certArray[i] = new X509CertImpl(certData);
        }
        return new Certificates(certArray);
    }

    public boolean set(String name, Certificates value) {
        if (value == null) {
            return false;
        }
        X509Certificate[] certArray = value.getCertificates();
        DerValue[] derValues = new DerValue[certArray.length];
        try (DerOutputStream derStream = new DerOutputStream()) {
            for (int i = 0; i < certArray.length; i++) {
                ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                try {
                    X509CertImpl certImpl = (X509CertImpl) certArray[i];
                    certImpl.encode(byteStream);
                    derValues[i] = new DerValue(byteStream.toByteArray());
                } catch (CertificateEncodingException e) {
                    return false;
                } catch (ClassCastException e) {
                    return false;
                }
            }
            derStream.putSequence(derValues);
            return set(name, derStream.toByteArray());
        } catch (IOException e) {
            return false;
        }
    }

    public byte[][] getInByteArrayArray(String name) throws IOException {
        byte[][] retval;

        byte[] byteValue = getInByteArray(name);
        if (byteValue == null) {
            return null;
        }
        DerInputStream in = new DerInputStream(byteValue);
        DerValue[] derValues = in.getSequence(5);
        retval = new byte[derValues.length][];
        for (int i = 0; i < derValues.length; i++) {
            retval[i] = derValues[i].getOctetString();
        }
        return retval;
    }

    public boolean set(String name, byte[][] value) {
        if (value == null) {
            return false;
        }

        DerValue[] derValues = new DerValue[value.length];
        try (DerOutputStream out = new DerOutputStream()) {
            for (int i = 0; i < value.length; i++) {
                derValues[i] = new DerValue(DerValue.tag_OctetString, value[i]);
            }
            out.putSequence(derValues);
            return set(name, out.toByteArray());
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Enumerate all attribute values in the AuthToken.
     *
     * @return Enumeration of all attribute names in this AuthToken.
     */
    public Enumeration<Object> getVals() {
        return (mAttrs.elements());
    }

    /**
     * Gets the name of the authentication manager instance that created
     * this token.
     *
     * @return The name of the authentication manager instance that created
     *         this token.
     */
    public String getAuthManagerInstName() {
        return ((String) mAttrs.get(TOKEN_AUTHMGR_INST_NAME));
    }

    /**
     * Gets the plugin name of the authentication manager that created this
     * token.
     *
     * @return The plugin name of the authentication manager that created this
     *         token.
     */
    public String getAuthManagerImplName() {
        return ((String) mAttrs.get(TOKEN_AUTHMGR_IMPL_NAME));
    }

    /**
     * Gets the time of authentication.
     *
     * @return The time of authentication
     */
    public Date getAuthTime() {
        return ((Date) mAttrs.get(TOKEN_AUTHTIME));
    }
}

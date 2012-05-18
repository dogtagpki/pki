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
package com.netscape.cmscore.base;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import netscape.security.pkcs.PKCS10;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.KeyGenInfo;
import com.netscape.cmsutil.util.Utils;

/**
 * This class represents a set of indexed arguments.
 * Each argument is indexed by a key, which can be
 * used during the argument retrieval.
 *
 * @version $Revision$, $Date$
 */
public class ArgBlock implements IArgBlock {

    /**
     *
     */
    private static final long serialVersionUID = -6054531129316353282L;
    /*==========================================================
     * variables
     *==========================================================*/
    public static final String CERT_NEW_REQUEST_HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String CERT_NEW_REQUEST_TRAILER = "-----END NEW CERTIFICATE REQUEST-----";
    public static final String CERT_REQUEST_HEADER = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String CERT_REQUEST_TRAILER = "-----END CERTIFICATE REQUEST-----";
    public static final String CERT_RENEWAL_HEADER = "-----BEGIN RENEWAL CERTIFICATE REQUEST-----";
    public static final String CERT_RENEWAL_TRAILER = "-----END RENEWAL CERTIFICATE REQUEST-----";

    private Hashtable<String, Object> mArgs = new Hashtable<String, Object>();

    private String mType = "unspecified-argblock";

    /*==========================================================
     * constructors
     *==========================================================*/
    /**
     * Constructs an argument block with the given hashtable values.
     *
     * @param realm the type of argblock - used for debugging the values
     */
    public ArgBlock(String realm, Hashtable<String, String> httpReq) {
        mType = realm;
        populate(httpReq);
    }

    /**
     * Constructs an argument block with the given hashtable values.
     *
     * @param httpReq hashtable keys and values
     */
    public ArgBlock(Hashtable<String, String> httpReq) {
        populate(httpReq);
    }

    private void populate(Hashtable<String, String> httpReq) {
        // Add all parameters from the request
        Enumeration<String> e = httpReq.keys();

        if (e != null) {
            while (e.hasMoreElements()) {
                String name = e.nextElement();
                String value = httpReq.get(name);

                addStringValue(name, value);
            }
        }
    }

    /**
     * Constructs an empty argument block.
     */
    public ArgBlock() {
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * Checks if this argument block contains the given key.
     *
     * @param n key
     * @return true if key is present
     */
    public boolean isValuePresent(String n) {
        CMS.traceHashKey(mType, n);
        if (mArgs.get(n) != null) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Adds string-based value into this argument block.
     *
     * @param n key
     * @param v value
     * @return value
     */
    public Object addStringValue(String n, String v) {
        if (v == null) {
            return mArgs.put(n, Character.valueOf((char) 0));
        } else {
            return mArgs.put(n, v);
        }
    }

    /**
     * Retrieves argument value as string.
     *
     * @param n key
     * @return argument value as string
     * @exception EBaseException failed to retrieve value
     */
    public String getValueAsString(String n) throws EBaseException {
        String t = (String) mArgs.get(n);
        CMS.traceHashKey(mType, n, t);

        if (t != null) {
            return t;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", n));
        }
    }

    /**
     * Retrieves argument value as string.
     *
     * @param n key
     * @param def default value to be returned if key is not present
     * @return argument value as string
     */
    public String getValueAsString(String n, String def) {
        String val = (String) mArgs.get(n);
        CMS.traceHashKey(mType, n, val, def);

        if (val != null) {
            return val;
        } else {
            return def;
        }
    }

    /**
     * Retrieves argument value as integer.
     *
     * @param n key
     * @return argument value as int
     * @exception EBaseException failed to retrieve value
     */
    public int getValueAsInt(String n) throws EBaseException {
        if (mArgs.get(n) != null) {
            CMS.traceHashKey(mType, n, (String) mArgs.get(n));
            try {
                return new Integer((String) mArgs.get(n)).intValue();
            } catch (NumberFormatException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_TYPE", n, e.toString()));
            }
        } else {
            CMS.traceHashKey(mType, n, "<notpresent>");
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", n));
        }
    }

    /**
     * Retrieves argument value as integer.
     *
     * @param n key
     * @param def default value to be returned if key is not present
     * @return argument value as int
     */
    public int getValueAsInt(String n, int def) {
        CMS.traceHashKey(mType, n, (String) mArgs.get(n), "" + def);
        if (mArgs.get(n) != null) {
            try {
                return new Integer((String) mArgs.get(n)).intValue();
            } catch (NumberFormatException e) {
                return def;
            }
        } else {
            return def;
        }
    }

    /**
     * Retrieves argument value as big integer.
     *
     * @param n key
     * @return argument value as big integer
     * @exception EBaseException failed to retrieve value
     */
    public BigInteger getValueAsBigInteger(String n)
            throws EBaseException {
        String v = (String) mArgs.get(n);

        if (v != null) {
            try {
                return new BigInteger(v, 10);
            } catch (NumberFormatException e) {
                try {
                    return new BigInteger(v, 16);
                } catch (NumberFormatException ex) {
                    throw new EBaseException(
                            CMS.getUserMessage("CMS_BASE_INVALID_ATTR_TYPE", n, ex.toString()));
                }
            }
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", n));
        }
    }

    /**
     * Retrieves argument value as big integer.
     *
     * @param n key
     * @param def default value to be returned if key is not present
     * @return argument value as big integer
     */
    public BigInteger getValueAsBigInteger(String n, BigInteger def) {
        try {
            return getValueAsBigInteger(n);
        } catch (EBaseException e) {
            return def;
        }
    }

    /**
     * Retrieves argument value as object
     *
     * @param n key
     * @return argument value as object
     * @exception EBaseException failed to retrieve value
     */
    public Object getValue(Object n) throws EBaseException {
        if (mArgs.get(n) != null) {
            return mArgs.get(n);
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", (String) n));
        }
    }

    /**
     * Retrieves argument value as object
     *
     * @param n key
     * @param def default value to be returned if key is not present
     * @return argument value as object
     */
    public Object getValue(Object n, Object def) {
        if (mArgs.get(n) != null) {
            return mArgs.get(n);
        } else {
            return def;
        }
    }

    /**
     * Gets boolean value. They should be "true" or "false".
     *
     * @param name name of the input type
     * @return boolean type: <code>true</code> or <code>false</code>
     * @exception EBaseException failed to retrieve value
     */
    public boolean getValueAsBoolean(String name) throws EBaseException {
        String val = (String) mArgs.get(name);
        CMS.traceHashKey(mType, name, val);

        if (val != null) {
            if (val.equalsIgnoreCase("true") ||
                    val.equalsIgnoreCase("on"))
                return true;
            else
                return false;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", name));
        }
    }

    /**
     * Gets boolean value. They should be "true" or "false".
     *
     * @param name name of the input type
     * @return boolean type: <code>true</code> or <code>false</code>
     */
    public boolean getValueAsBoolean(String name, boolean def) {
        boolean val;

        try {
            val = getValueAsBoolean(name);
            return val;
        } catch (EBaseException e) {
            return def;
        }
    }

    /**
     * Gets KeyGenInfo
     *
     * @param name name of the input type
     * @param verify true if signature validation is required
     * @exception EBaseException
     * @return KeyGenInfo object
     */
    public KeyGenInfo getValueAsKeyGenInfo(String name, KeyGenInfo def)
            throws EBaseException {
        KeyGenInfo keyGenInfo;

        CMS.traceHashKey(mType, name);
        if (mArgs.get(name) != null) {
            try {
                keyGenInfo = new KeyGenInfo((String) mArgs.get(name));
            } catch (IOException e) {
                return def;
            }

        } else {
            return def;
        }
        return keyGenInfo;
    }

    /**
     * Gets PKCS10 request. This pkcs10 attribute does not
     * contain header information.
     *
     * @param name name of the input type
     * @return pkcs10 request
     * @exception EBaseException failed to retrieve value
     */
    public PKCS10 getValueAsRawPKCS10(String name) throws EBaseException {
        PKCS10 request;

        if (mArgs.get(name) != null) {
            CMS.traceHashKey(mType, name, (String) mArgs.get(name));

            String tempStr = unwrap((String) mArgs.get(name), false);

            if (tempStr == null) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE", name, "Empty Content"));
            }
            try {
                request = decodePKCS10(tempStr);
            } catch (Exception e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE", name, e.toString()));
            }
        } else {
            CMS.traceHashKey(mType, name, "<notpresent>");
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", name));
        }

        return request;
    }

    /**
     * Gets PKCS10 request. This pkcs10 attribute does not
     * contain header information.
     *
     * @param name name of the input type
     * @param def default PKCS10
     * @return pkcs10 request
     * @exception EBaseException failed to retrieve value
     */
    public PKCS10 getValueAsRawPKCS10(String name, PKCS10 def)
            throws EBaseException {
        PKCS10 request;

        CMS.traceHashKey(mType, name);
        if (mArgs.get(name) != null) {

            String tempStr = unwrap((String) mArgs.get(name), false);

            if (tempStr == null) {
                return def;
            }
            try {
                request = decodePKCS10(tempStr);
            } catch (Exception e) {
                return def;
            }
        } else {
            return def;
        }
        return request;
    }

    /**
     * Retrieves PKCS10
     *
     * @param name name of the input type
     * @param checkheader true if header must be present
     * @return PKCS10 object
     * @exception EBaseException failed to retrieve value
     */
    public PKCS10 getValueAsPKCS10(String name, boolean checkheader)
            throws EBaseException {
        PKCS10 request;

        CMS.traceHashKey(mType, name);
        if (mArgs.get(name) != null) {

            String tempStr = unwrap((String) mArgs.get(name), checkheader);

            if (tempStr == null) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE", name, "Empty Content"));
            }
            try {
                request = decodePKCS10(tempStr);
            } catch (Exception e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE", name, e.toString()));
            }
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", name));
        }

        return request;
    }

    /**
     * Retrieves PKCS10
     *
     * @param name name of the input type
     * @param checkheader true if header must be present
     * @param def default PKCS10
     * @return PKCS10 object
     * @exception EBaseException
     */
    public PKCS10 getValueAsPKCS10(
            String name, boolean checkheader, PKCS10 def)
            throws EBaseException {
        PKCS10 request;

        CMS.traceHashKey(mType, name);

        if (mArgs.get(name) != null) {

            String tempStr = unwrap((String) mArgs.get(name), checkheader);

            if (tempStr == null) {
                return def;
            }
            try {
                request = decodePKCS10(tempStr);
            } catch (Exception e) {
                return def;
            }
        } else {
            return def;
        }

        return request;
    }

    /**
     * Retrieves PKCS10
     *
     * @param name name of the input type
     * @param def default PKCS10
     * @return PKCS10 object
     * @exception EBaseException
     */
    public PKCS10 getValuePKCS10(String name, PKCS10 def)
            throws EBaseException {
        PKCS10 request;
        String p10b64 = (String) mArgs.get(name);
        CMS.traceHashKey(mType, name);

        if (p10b64 != null) {

            try {
                request = decodePKCS10(p10b64);
                return request;
            } catch (Exception e) {
                return def;
            }
        } else {
            return def;
        }
    }

    /**
     * Sets argument into this block.
     *
     * @param name key
     * @param ob value
     */
    public void set(String name, Object ob) {
        mArgs.put(name, ob);
    }

    /**
     * Retrieves argument.
     *
     * @param name key
     * @return object value
     */
    public Object get(String name) {
        CMS.traceHashKey(mType, name);
        return mArgs.get(name);
    }

    /**
     * Deletes argument by the given key.
     *
     * @param name key
     */
    public void delete(String name) {
        mArgs.remove(name);
    }

    /**
     * Retrieves a list of argument keys.
     *
     * @return a list of string-based keys
     */
    public Enumeration<String> getElements() {
        return mArgs.keys();
    }

    /**
     * Retrieves a list of argument keys.
     *
     * @return a list of string-based keys
     */
    public Enumeration<String> elements() {
        return mArgs.keys();
    }

    /**
     * Adds long-type arguments to this block.
     *
     * @param n key
     * @param v value
     * @return value
     */
    public Object addLongValue(String n, long v) {
        return mArgs.put(n, Long.valueOf(v));
    }

    /**
     * Adds integer-type arguments to this block.
     *
     * @param n key
     * @param v value
     * @return value
     */
    public Object addIntegerValue(String n, int v) {
        return mArgs.put(n, Integer.valueOf(v));
    }

    /**
     * Adds boolean-type arguments to this block.
     *
     * @param n key
     * @param v value
     * @return value
     */
    public Object addBooleanValue(String n, boolean v) {
        return mArgs.put(n, Boolean.valueOf(v));
    }

    /**
     * Adds integer-type arguments to this block.
     *
     * @param n key
     * @param v value
     * @param radix radix
     * @return value
     */
    public Object addBigIntegerValue(String n, BigInteger v, int radix) {
        return mArgs.put(n, v.toString(radix));
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    /**
     * Unwrap PKCS10 Package
     *
     * @param request string formated PKCS10 request
     * @exception EBaseException
     * @return Base64Encoded PKCS10 request
     */
    private String unwrap(String request, boolean checkHeader)
            throws EBaseException {
        String unwrapped;
        String header = null;
        int head = -1;
        int trail = -1;

        // check for "-----BEGIN NEW CERTIFICATE REQUEST-----";
        if (header == null) {
            head = request.indexOf(CERT_NEW_REQUEST_HEADER);
            trail = request.indexOf(CERT_NEW_REQUEST_TRAILER);

            if (!(head == -1 && trail == -1)) {
                header = CERT_NEW_REQUEST_HEADER;
            }
        }

        // check for "-----BEGIN CERTIFICATE REQUEST-----";
        if (header == null) {
            head = request.indexOf(CERT_REQUEST_HEADER);
            trail = request.indexOf(CERT_REQUEST_TRAILER);

            // If this is not a request header, check if this is a renewal
            // header.
            if (!(head == -1 && trail == -1)) {
                header = CERT_REQUEST_HEADER;

            }
        }

        // check for "-----BEGIN RENEWAL CERTIFICATE REQUEST-----";
        if (header == null) {
            head = request.indexOf(CERT_RENEWAL_HEADER);
            trail = request.indexOf(CERT_RENEWAL_TRAILER);
            if (!(head == -1 && trail == -1)) {
                header = CERT_RENEWAL_HEADER;
            }
        }

        // Now validate if any headers or trailers are in place
        if (head == -1 && checkHeader) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_MISSING_PKCS10_HEADER"));
        }
        if (trail == -1 && checkHeader) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_MISSING_PKCS10_TRAILER"));
        }

        if (header != null) {
            unwrapped = request.substring(head + header.length(), trail);
        } else {
            unwrapped = request;
        }

        // strip all the crtl-characters (i.e. \r\n)
        StringTokenizer st = new StringTokenizer(unwrapped, "\t\r\n ");
        StringBuffer stripped = new StringBuffer();

        while (st.hasMoreTokens()) {
            stripped.append(st.nextToken());
        }

        return stripped.toString();
    }

    /**
     * Decode Der encoded PKCS10 certifictae Request
     *
     * @param base64Request Base64 Encoded Certificate Request
     * @exception Exception
     * @return PKCS10
     */
    private PKCS10 decodePKCS10(String base64Request)
            throws EBaseException {
        PKCS10 pkcs10 = null;

        try {
            byte[] decodedBytes = Utils.base64decode(base64Request);

            pkcs10 = new PKCS10(decodedBytes);
        } catch (NoSuchProviderException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (IOException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (SignatureException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        }

        return pkcs10;
    }

}

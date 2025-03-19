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
import java.util.Enumeration;
import java.util.Hashtable;

import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.KeyGenInfo;
import com.netscape.cmscore.apps.CMS;

/**
 * This class represents a set of indexed arguments.
 * Each argument is indexed by a key, which can be
 * used during the argument retrieval.
 *
 * Set of cooperating instances of this class may exploit
 * dot-separated attribute names to provide seamless access to the
 * attributes of attribute value which also implements AttrSet
 * interface as if it was direct attribute of the container
 * E.g., ((AttrSet)container.get("x")).get("y") is equivalent to
 * container.get("x.y");
 */
public class ArgBlock {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ArgBlock.class);
    /*==========================================================
     * variables
     *==========================================================*/

    private Hashtable<String, Object> mArgs = new Hashtable<>();

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
        logger.trace("GET r={},k={}", mType, n);
        return mArgs.get(n) != null;
    }

    /**
     * Adds string-based value into this argument block.
     *
     * @param n key
     * @param v value
     * @return value
     */
    public Object addStringValue(String n, String v) {
        return v == null ? mArgs.put(n, Character.valueOf((char) 0)) : mArgs.put(n, v);
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
        logger.trace("GET r={},k={},v={}", mType, n, CMS.isSensitive(n)?": (sensitive)":t);

        if (t == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", n));
        }
        return t;
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
        logger.trace("GET r={},k={},v={},d={}", mType, n, CMS.isSensitive(n)?": (sensitive)":val, def);

        return val == null ? def : val;
    }

    /**
     * Retrieves argument value as integer.
     *
     * @param n key
     * @return argument value as int
     * @exception EBaseException failed to retrieve value
     */
    public int getValueAsInt(String n) throws EBaseException {
        if (mArgs.get(n) == null) {
            logger.trace("GET r={},k={},v={}", mType, n, "<notpresent>");
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", n));
        }
        logger.trace("GET r={},k={},v={}", mType, n, mArgs.get(n));
        try {
            return Integer.valueOf((String) mArgs.get(n)).intValue();
        } catch (NumberFormatException e) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTR_TYPE", n, e.toString()));
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
        logger.trace("GET r={},k={},v={},d={}", mType, n, mArgs.get(n), def);
        if (mArgs.get(n) == null) {
            return def;
        }
        try {
            return Integer.valueOf((String) mArgs.get(n)).intValue();
        } catch (NumberFormatException e) {
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

        if (v == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", n));
        }
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
        if (mArgs.get(n) == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", (String) n));
        }
        return mArgs.get(n);
    }

    /**
     * Retrieves argument value as object
     *
     * @param n key
     * @param def default value to be returned if key is not present
     * @return argument value as object
     */
    public Object getValue(Object n, Object def) {
        return mArgs.get(n) == null ? def : mArgs.get(n);
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
        logger.trace("GET r={},k={},v={}", mType, name, val);

        if (val == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", name));
        }
        return val.equalsIgnoreCase("true") || val.equalsIgnoreCase("on");
    }

    /**
     * Gets boolean value. They should be "true" or "false".
     *
     * @param name name of the input type
     * @param def Default value to return.
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
     * @param def default value to return
     * @exception EBaseException On error.
     * @return KeyGenInfo object
     */
    public KeyGenInfo getValueAsKeyGenInfo(String name, KeyGenInfo def)
            throws EBaseException {

        logger.trace("GET r={},k={}", mType, name);
        KeyGenInfo keyGenInfo;

        if (mArgs.get(name) == null) {
            return def;
        }
        try {
            keyGenInfo = new KeyGenInfo((String) mArgs.get(name));
        } catch (IOException e) {
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

        if (mArgs.get(name) == null) {
            logger.trace("GET r={},k={},v={}", mType, name, "<notpresent>");
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", name));
        }
        logger.trace("GET r={},k={},v={}", mType, name, mArgs.get(name));

        String tempStr = CertUtil.unwrapCSR((String) mArgs.get(name), false);

        if (tempStr == null) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE", name, "Empty Content"));
        }
        try {
            request = CertUtil.decodePKCS10(tempStr);
        } catch (Exception e) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE", name, e.toString()));
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

        logger.trace("GET r={},k={}", mType, name);
        PKCS10 request;

        if (mArgs.get(name) == null) {
            return def;
        }
        String tempStr = CertUtil.unwrapCSR((String) mArgs.get(name), false);

        if (tempStr == null) {
            return def;
        }
        try {
            request = CertUtil.decodePKCS10(tempStr);
        } catch (Exception e) {
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

        logger.trace("GET r={},k={}", mType, name);
        PKCS10 request;

        if (mArgs.get(name) == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND", name));
        }
        String tempStr = CertUtil.unwrapCSR((String) mArgs.get(name), checkheader);

        if (tempStr == null) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE", name, "Empty Content"));
        }
        try {
            request = CertUtil.decodePKCS10(tempStr);
        } catch (Exception e) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE", name, e.toString()));
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

        logger.trace("GET r={},k={}", mType, name);
        PKCS10 request;

        if (mArgs.get(name) == null) {
            return def;
        }
        String tempStr = CertUtil.unwrapCSR((String) mArgs.get(name), checkheader);

        if (tempStr == null) {
            return def;
        }
        try {
            request = CertUtil.decodePKCS10(tempStr);
        } catch (Exception e) {
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

        logger.trace("GET r={},k={}", mType, name);
        PKCS10 request;
        String p10b64 = (String) mArgs.get(name);

        if (p10b64 == null) {
            return def;
        }
        try {
            request = CertUtil.decodePKCS10(p10b64);
            return request;
        } catch (Exception e) {
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
        logger.trace("GET r={},k={}", mType, name);
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
}

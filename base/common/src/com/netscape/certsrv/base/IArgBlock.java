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
package com.netscape.certsrv.base;

import java.util.*;
import java.io.*;
import netscape.security.pkcs.*;
import java.security.*;
import java.math.BigInteger;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.BaseResources;


/**
 * This interface defines the abstraction for the generic collection
 * of attributes indexed by string names.
 * Set of cooperating implementations of this interface may exploit
 * dot-separated attribute names to provide seamless access to the
 * attributes of attribute value  which also implements AttrSet
 * interface as if it was direct attribute of the container
 * E.g., ((AttrSet)container.get("x")).get("y") is equivalent to
 * container.get("x.y");
 * <p>
 *
 * @version $Revision$, $Date$
 **/
public interface IArgBlock extends Serializable {

    /**
     * Checks if this argument block contains the given key.
     *
     * @param n key
     * @return true if key is present
     */
    public boolean isValuePresent(String n);
    /**
     * Adds string-based value into this argument block.
     *
     * @param n key
     * @param v value
     * @return value
     */
    public Object addStringValue(String n, String v);

    /**
     * Retrieves argument value as string.
     *
     * @param n key
     * @return argument value as string
     * @exception EBaseException failed to retrieve value
     */
    public String getValueAsString(String n) throws EBaseException;

    /**
     * Retrieves argument value as string.
     *
     * @param n key
     * @param def default value to be returned if key is not present
     * @return argument value as string
     */
    public String getValueAsString(String n, String def);

    /**
     * Retrieves argument value as integer.
     *
     * @param n key
     * @return argument value as int
     * @exception EBaseException failed to retrieve value
     */
    public int getValueAsInt(String n) throws EBaseException;    

    /**
     * Retrieves argument value as integer.
     *
     * @param n key
     * @param def default value to be returned if key is not present
     * @return argument value as int
     */
    public int getValueAsInt(String n, int def);

    /**
     * Retrieves argument value as big integer.
     *
     * @param n key
     * @return argument value as big integer
     * @exception EBaseException failed to retrieve value
     */
    public BigInteger getValueAsBigInteger(String n) throws EBaseException;

    /**
     * Retrieves argument value as big integer.
     *
     * @param n key
     * @param def default value to be returned if key is not present
     * @return argument value as big integer
     */
    public BigInteger getValueAsBigInteger(String n, BigInteger def);

    /**
     * Retrieves argument value as object
     *
     * @param n key
     * @return argument value as object
     * @exception EBaseException failed to retrieve value
     */
    public Object getValue(Object n) throws EBaseException;

    /**
     * Retrieves argument value as object
     *
     * @param n key
     * @param def default value to be returned if key is not present
     * @return argument value as object
     */
    public Object getValue(Object n, Object def);

    /**
     * Gets boolean value. They should be "true" or "false".
     *
     * @param name name of the input type
     * @return boolean type: <code>true</code> or <code>false</code>
     * @exception EBaseException failed to retrieve value
     */
    public boolean getValueAsBoolean(String name) throws EBaseException;

    /**
     * Gets boolean value. They should be "true" or "false".
     *
     * @param name name of the input type
     * @param def  Default value to return.
     * @return boolean type: <code>true</code> or <code>false</code>
     */
    public boolean getValueAsBoolean(String name, boolean def);

    /**
     * Gets KeyGenInfo
     *
     * @param name name of the input type
     * @param def default value to return
     * @exception EBaseException On error.
     * @return KeyGenInfo object
     */
    public KeyGenInfo getValueAsKeyGenInfo(String name, KeyGenInfo def) throws EBaseException;

    /**
     * Gets PKCS10 request. This pkcs10 attribute does not
     * contain header information.
     *
     * @param name name of the input type
     * @return pkcs10 request
     * @exception EBaseException failed to retrieve value
     */
    public PKCS10 getValueAsRawPKCS10(String name) throws EBaseException;

    /**
     * Gets PKCS10 request. This pkcs10 attribute does not
     * contain header information.
     *
     * @param name name of the input type
     * @param def default PKCS10
     * @return pkcs10 request
     * @exception EBaseException failed to retrieve value
     */
    public PKCS10 getValueAsRawPKCS10(String name, PKCS10 def) throws EBaseException;

    /**
     * Retrieves PKCS10
     *
     * @param name name of the  input type
     * @param checkheader true if header must be present
     * @return PKCS10 object
     * @exception EBaseException failed to retrieve value
     */
    public PKCS10 getValueAsPKCS10(String name, boolean checkheader) throws EBaseException;

    /**
     * Retrieves PKCS10
     *
     * @param name name of the  input type
     * @param checkheader true if header must be present
     * @param def default PKCS10
     * @return PKCS10 object
     * @exception EBaseException on error
     */
    public PKCS10 getValueAsPKCS10(String name, boolean checkheader, PKCS10 def) throws EBaseException;

    /**
     * Retrieves PKCS10
     *
     * @param name name of the  input type
     * @param def default PKCS10
     * @return PKCS10 object
     * @exception EBaseException on error
     */
    public PKCS10 getValuePKCS10(String name, PKCS10 def) throws EBaseException;

    /**
     * Retrieves a list of argument keys.
     *
     * @return a list of string-based keys
     */
    public Enumeration elements();

    /**
     * Adds long-type arguments to this block.
     *
     * @param n key
     * @param v value
     * @return value
     */
    public Object addLongValue(String n, long v);

    /**
     * Adds integer-type arguments to this block.
     *
     * @param n key
     * @param v value
     * @return value
     */
    public Object addIntegerValue(String n, int v);

    /**
     * Adds boolean-type arguments to this block.
     *
     * @param n key
     * @param v value
     * @return value
     */
    public Object addBooleanValue(String n, boolean v);

    /**
     * Adds integer-type arguments to this block.
     *
     * @param n key
     * @param v value
     * @param radix radix
     * @return value
     */
    public Object addBigIntegerValue(String n, BigInteger v, int radix);

    /**
     * Sets argument into this block.
     *
     * @param name key
     * @param obj value
     */
    public void set(String name, Object obj);

    /**
     * Retrieves argument.
     *
     * @param name key
     * @return object value
     */
    public Object get(String name);

    /**
     * Deletes argument by the given key.
     *
     * @param name key
     */
    public void delete(String name);

    /**
     * Retrieves a list of argument keys.
     *
     * @return a list of string-based keys
     */
    public Enumeration getElements();
}

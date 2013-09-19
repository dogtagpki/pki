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

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Map;

/**
 * An interface represents a configuration store.
 * A configuration store is an abstraction of a hierarchical store
 * to keep arbitrary data indexed by string names.
 * <p>
 * In the following example:
 *
 * <pre>
 *      param1=value1
 *      configStore1.param11=value11
 *      configStore1.param12=value12
 *      configStore1.subStore1.param111=value111
 *      configStore1.subStore1.param112=value112
 *      configStore2.param21=value21
 * </pre>
 *
 * The top config store has parameters <i>param1</i> and sub-stores <i>configStore1</i> and <i>configStore2</i>. <br>
 * The following illustrates how a config store is used.
 *
 * <pre>
 * // the top config store is passed to the following method.
 * public void init(IConfigStore config) throws EBaseException {
 *     IConfigStore store = config;
 *     String valx = config.getString(&quot;param1&quot;);
 *     // valx is &quot;value1&quot; &lt;p&gt;
 *
 *     IConfigStore substore1 = config.getSubstore(&quot;configStore1&quot;);
 *     String valy = substore1.getString(&quot;param11&quot;);
 *     // valy is &quot;value11&quot; &lt;p&gt;
 *
 *     IConfigStore substore2 = config.getSubstore(&quot;configStore2&quot;);
 *     String valz = substore2.getString(&quot;param21&quot;);
 *     // valz is &quot;value21&quot; &lt;p&gt;
 * }
 * </pre>
 *
 * @version $Revision$, $Date$
 */
public interface IConfigStore extends ISourceConfigStore {

    /**
     * Gets the name of this Configuration Store.
     * <P>
     *
     * @return The name of this Configuration store
     */
    public String getName();

    /**
     * Retrieves the value of the given property as a string.
     * <p>
     *
     * @param name The name of the property to get
     * @return The value of the property as a String
     * @exception EPropertyNotFound If the property is not present
     * @exception EBaseException If an internal error occurred
     */
    public String getString(String name)
            throws EPropertyNotFound, EBaseException;

    /**
     * Retrieves the value of a given property as a string or the
     * given default value if the property is not present.
     * <P>
     *
     * @param name The property to retrive
     * @param defval The default value to return if the property is not present
     * @return The roperty value as a string
     * @exception EBaseException If an internal error occurred
     */
    public String getString(String name, String defval)
            throws EBaseException;

    /**
     * Stores a property and its value as a string.
     * <p>
     *
     * @param name The name of the property
     * @param value The value as a string
     */
    public void putString(String name, String value);

    /**
     * Retrieves the value of a property as a byte array.
     * <P>
     *
     * @param name The property name
     * @return The property value as a byte array
     * @exception EPropertyNotFound If the property is not present
     * @exception EBaseException If an internal error occurred
     */
    public byte[] getByteArray(String name)
            throws EPropertyNotFound, EBaseException;

    /**
     * Retrieves the value of a property as a byte array, using the
     * given default value if property is not present.
     * <P>
     *
     * @param name The name of the property
     * @param defval The default value if the property is not present.
     * @return The property value as a byte array.
     * @exception EBaseException If an internal error occurred
     */
    public byte[] getByteArray(String name, byte defval[])
            throws EBaseException;

    /**
     * Stores the given property and value as a byte array.
     * <p>
     *
     * @param name The property name
     * @param value The value as a byte array to store
     */
    public void putByteArray(String name, byte value[]);

    /**
     * Retrieves the given property as a boolean.
     * <P>
     *
     * @param name The name of the property as a string.
     * @return The value of the property as a boolean.
     * @exception EPropertyNotFound If the property is not present
     * @exception EBaseException If an internal error occurred
     */
    public boolean getBoolean(String name)
            throws EPropertyNotFound, EBaseException;

    /**
     * Retrieves the given property as a boolean.
     * <P>
     *
     * @param name The name of the property
     * @param defval The default value to turn as a boolean if
     *            property is not present
     * @return The value of the property as a boolean.
     * @exception EBaseException If an internal error occurred
     */
    public boolean getBoolean(String name, boolean defval)
            throws EBaseException;

    /**
     * Stores the given property and its value as a boolean.
     * <P>
     *
     * @param name The property name
     * @param value The value as a boolean
     */
    public void putBoolean(String name, boolean value);

    /**
     * Retrieves the given property as an integer.
     * <P>
     *
     * @param name The property name
     * @return The property value as an integer
     * @exception EPropertyNotFound If property is not found
     * @exception EBaseException If an internal error occurred
     */
    public int getInteger(String name)
            throws EPropertyNotFound, EBaseException;

    /**
     * Retrieves the given property as an integer.
     * <P>
     *
     * @param name The property name
     * @return int The default value to return as an integer
     * @exception EBaseException If the value cannot be converted to a
     *                integer
     */
    public int getInteger(String name, int defval)
            throws EBaseException;

    /**
     * Sets a property and its value as an integer.
     * <P>
     *
     * @param name parameter name
     * @param value integer value
     */
    public void putInteger(String name, int value);

    /**
     * Retrieves the given property as a big integer.
     * <P>
     *
     * @param name The property name
     * @return The property value as a big integer
     * @exception EPropertyNotFound If property is not found
     * @exception EBaseException If an internal error occurred
     */
    public BigInteger getBigInteger(String name)
            throws EPropertyNotFound, EBaseException;

    /**
     * Retrieves the given property as a big integer.
     * <P>
     *
     * @param name The property name
     * @return int The default value to return as a big integer
     * @exception EBaseException If the value cannot be converted to a
     *                integer
     */
    public BigInteger getBigInteger(String name, BigInteger defval)
            throws EBaseException;

    /**
     * Sets a property and its value as an integer.
     * <P>
     *
     * @param name parameter name
     * @param value big integer value
     */
    public void putBigInteger(String name, BigInteger value);

    /**
     * Creates a nested sub-store with the specified name.
     * <P>
     *
     * @param name The name of the sub-store
     * @return The sub-store created
     */
    public IConfigStore makeSubStore(String name);

    /**
     * Retrieves the given sub-store.
     * <P>
     *
     * @param name The name of the sub-store
     * @return The sub-store
     */
    public IConfigStore getSubStore(String name);

    /**
     * Removes sub-store with the given name.
     * (Removes all properties and sub-stores under this sub-store.)
     * <P>
     *
     * @param name The name of the sub-store to remove
     */
    public void removeSubStore(String name);

    public void remove(String name);

    /**
     * Retrives and enumeration of all properties in this config-store.
     *
     * @return An enumeration of all properties in this config-store
     */
    public Enumeration<String> getPropertyNames();

    /**
     * Returns an enumeration of the names of the substores of
     * this config-store.
     * <P>
     *
     * @return An enumeration of the names of the sub-stores of this
     *         config-store
     */
    public Enumeration<String> getSubStoreNames();

    /**
     * Commits all the data into file immediately.
     *
     * @param createBackup true if a backup file should be created
     * @exception EBaseException failed to commit
     */
    public void commit(boolean createBackup) throws EBaseException;

    /**
     * Return the number of items in this substore
     */
    public int size();

    /**
     * Get properties as a map.
     */
    public Map<String, String> getProperties() throws EBaseException;
}

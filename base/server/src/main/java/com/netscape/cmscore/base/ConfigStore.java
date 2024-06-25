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

import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.util.Base64OutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotDefined;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.cmscore.apps.CMS;

/**
 * A class represents a in-memory configuration store.
 *
 * A configuration store is an abstraction of a hierarchical store
 * to keep arbitrary data indexed by string names.
 *
 * In the following example:
 *
 * <pre>{@Code
 * param1=value1
 * configStore1.param11=value11
 * configStore1.param12=value12
 * configStore1.subStore1.param111=value111
 * configStore1.subStore1.param112=value112
 * configStore2.param21=value21
 * }</pre>
 *
 * The top config store has parameters <i>param1</i> and sub-stores <i>configStore1</i> and <i>configStore2</i>. <br>
 * The following illustrates how a config store is used.
 *
 * <pre>{@Code
 * // the top config store is passed to the following method.
 * public void init(ConfigStore config) throws EBaseException {
 *     ConfigStore store = config;
 *     String valx = config.getString(&quot;param1&quot;);
 *     // valx is &quot;value1&quot;
 *
 *     ConfigStore substore1 = config.getSubStore(&quot;configStore1&quot;);
 *     String valy = substore1.getString(&quot;param11&quot;);
 *     // valy is &quot;value11&quot;
 *
 *     ConfigStore substore2 = config.getSubStore(&quot;configStore2&quot;);
 *     String valz = substore2.getString(&quot;param21&quot;);
 *     // valz is &quot;value21&quot;
 * }
 * }</pre>
 *
 * Note this class takes advantage of the recursive nature of
 * property names. The current property prefix is kept in
 * mStoreName and the mSource usually points back to another
 * occurance of the same ConfigStore, with longer mStoreName. IE
 *
 * <pre>{@Code
 * 	cms.ca0.http.service0 -> mSource=ConfigStore ->
 * 		cms.ca0.http -> mSource=ConfigStore ->
 * 			cms.ca0 -> mSource=ConfigStore ->
 * 					cms -> mSource=SourceConfigStore -> Properties
 * }</pre>
 *
 * The chain ends when the store name is reduced down to it's original
 * value.
 */
public class ConfigStore implements Cloneable {

    public final static Logger logger = LoggerFactory.getLogger(ConfigStore.class);

    protected static final String PROP_SUBSTORES = "substores";

    /**
     * The name of this substore
     */
    protected String mStoreName;

    /**
     * The source data for this substore
     */
    protected SimpleProperties mSource;

    protected ConfigStorage storage;

    public ConfigStore() {
        mSource = new SimpleProperties();
    }

    public ConfigStore(ConfigStorage storage) {
        mSource = new SimpleProperties();
        this.storage = storage;
    }

    /**
     * Constructs a property configuration store. This must
     * be a brand new store without properties. The subclass
     * must be a SourceConfigStore.
     *
     * @param storeName property store name
     * @exception EBaseException failed to create configuration
     */
    public ConfigStore(String storeName) {
        mSource = new SimpleProperties();
        mStoreName = storeName;
    }

    /**
     * Constructs a configuration store. The constructor is
     * a helper class for substores. Source is the one
     * that stores all the parameters. Each substore only
     * store a substore name, and a reference to the source.
     *
     * @param name store name
     * @param source list of properties
     * @exception EBaseException failed to create configuration
     */
    protected ConfigStore(String name, SimpleProperties source) {
        mStoreName = name;
        mSource = source;
    }

    /**
     * Returns the name of this store.
     *
     * @return store name
     */
    public String getName() {
        return mStoreName;
    }

    public ConfigStorage getStorage() {
        return storage;
    }

    /**
     * Retrieves a property from the configuration file.
     *
     * @param name property name
     * @return property value
     */
    public String get(String name) {
        return mSource.get(getFullName(name));
    }

    /**
     * Retrieves a property from the configuration file. Does not prepend
     * the config store name to the property.
     *
     * @param name property name
     * @return property value
     */
    private String nakedGet(String name) {
        return mSource.get(name);
    }

    /**
     * Puts a property into the configuration file. The
     * values wont be updated to the file until save
     * method is invoked.
     *
     * @param name property name
     * @param value property value
     */
    public String put(String name, String value) {
        String property = getFullName(name);
        logger.debug("Setting " + property + "=" + value);
        return mSource.put(property, value);
    }

    /**
     * Removes a property from the configuration file.
     *
     * @param name property name
     */
    public void remove(String name) {
        mSource.remove(getFullName(name));
    }

    /**
     * Returns an enumeration of the config store's keys, hidding the store
     * name.
     *
     * @return a list of keys
     * @see java.util.Hashtable#elements
     * @see java.util.Enumeration
     */
    public Enumeration<String> keys() {
        Hashtable<String, String> h = new Hashtable<>();
        enumerate(h);
        return h.keys();
    }

    /**
     * Retrieves lexicographically sorted properties as a map.
     *
     * @return map
     */
    public Map<String, String> getProperties() {
        Map<String, String> map = new TreeMap<>();
        enumerate(map);
        return map;
    }

    /**
     * Return the number of items in this substore
     */
    public int size() {
        Hashtable<String, String> h = new Hashtable<>();
        enumerate(h);
        return h.size();
    }

    /**
     * Fills the given map with all key/value pairs in the current
     * config store, removing the config store name prefix
     *
     * @param map the map
     */
    private synchronized void enumerate(Map<String, String> map) {
        Enumeration<String> e = mSource.keys();
        // We only want the keys which match the current substore name
        // without the current substore prefix.  This code works even
        // if mStoreName is null.
        String fullName = getFullName("");
        int kIndex = fullName.length();

        while (e.hasMoreElements()) {
            String key = e.nextElement();

            if (key.startsWith(fullName)) {
                map.put(key.substring(kIndex), nakedGet(key));
            }
        }
    }

    /**
     * Clear the config store.
     */
    public synchronized void clear() {
        mSource.clear();
    }

    /**
     * Load config from storage storage (file or LDAP).
     * @exception Exception If an error occurs while loading.
     */
    public void load() throws Exception {
        if (storage != null) {
            storage.load(this);
        }
    }

    /**
     * Store config into storage (file or LDAP).
     *
     * @param createBackup true if a backup file should be created
     * @exception EBaseException failed to commit
     */
    public void commit(boolean createBackup) throws EBaseException {
        if (storage != null) {
            storage.commit(this, createBackup);
        }
    }

    /**
     * Reads a config store from an input stream.
     *
     * @param in input stream where properties are located
     * @exception IOException failed to load
     */
    public synchronized void load(InputStream in) throws IOException {
        mSource.load(in);
    }

    /**
     * Stores this config store to the specified output stream.
     *
     * @param out outputstream where the properties are saved
     */
    public synchronized void store(OutputStream out) throws Exception {
        try (PrintWriter pw = new PrintWriter(out)) {
            Map<String, String> map = getProperties();
            for (String name : map.keySet()) {
                String value = map.get(name);
                pw.println(name + "=" + value);
            }
        }
    }

    /**
     * Retrieves the value of the given property as a string.
     *
     * @param name The name of the property to get
     * @return The value of the property as a String
     * @exception EPropertyNotFound If the property is not present
     * @exception EBaseException If an internal error occurred
     */
    public String getString(String name) throws EBaseException {
        String str = get(name);

        if (str == null) {
            logger.trace("Property {} not found", getFullName(name));
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", getFullName(name)));
        }
        // should we check for empty string ?
        // if (str.length() == 0) {
        //	throw new EPropertyNotDefined(getName() + "." + name);
        // }
        String ret = null;

        try {
            ret = new String(str.getBytes(), "UTF8").trim();
        } catch (java.io.UnsupportedEncodingException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_UTF8_NOT_SUPPORTED"));
        }

        logger.trace("Getting {}={}", getFullName(name), ret);
        return ret;
    }

    /**
     * Retrieves the value of a given property as a string or the
     * given default value if the property is not present.
     *
     * @param name property name
     * @param defval the default object to return if name does not exist
     * @return property value
     * @exception EBaseException If an internal error occurred
     */
    public String getString(String name, String defval) throws EBaseException {
        String val;

        try {
            val = getString(name);
        } catch (EPropertyNotFound e) {
            val = defval;
        }

        logger.trace("Getting {}={}", getFullName(name), val);
        return val;
    }

    /**
     * Puts property value into this configuration store.
     *
     * @param name property key
     * @param value property value
     */
    public void putString(String name, String value) {
        put(name, value);
    }

    /**
     * Retrieves a byte array from the configuration file.
     *
     * @param name property name
     * @return The property value as a byte array
     * @exception EPropertyNotFound If the property is not present
     * @exception IllegalArgumentException if name is not set or is null.
     *
     * @return property value
     */
    public byte[] getByteArray(String name) throws EBaseException {
        byte[] arr = getByteArray(name, new byte[0]);

        if (arr.length == 0) {
            logger.trace("Property {} not found", getFullName(name));
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", getName() + "." + name));
        }
        return arr;
    }

    /**
     * Retrieves the value of a property as a byte array, using the
     * given default value if property is not present.
     *
     * @param name The name of the property
     * @param defval The default value if the property is not present.
     * @return The property value as a byte array.
     * @exception EBaseException If an internal error occurred
     */
    public byte[] getByteArray(String name, byte defval[])
            throws EBaseException {
        String str = get(name);
        byte[] value;

        if (str == null || str.length() == 0) {
            value = defval;
        } else {
            value = Utils.base64decode(str);
        }

        logger.trace("Getting {}={}", getFullName(name), "<bytearray>");
        return value;
    }

    /**
     * Puts byte array into this configuration store.
     *
     * @param name property key
     * @param value byte array
     */
    public void putByteArray(String name, byte value[]) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (Base64OutputStream b64 = new Base64OutputStream(new
                PrintStream(new FilterOutputStream(output)))) {
            b64.write(value);
            b64.flush();

            // 8859 contains all the base-64 chars, so there are no
            // internationalization problems here
            put(name, output.toString("8859_1"));
        } catch (IOException e) {
            logger.warn("Base-64 encoding of configuration information failed: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves the given property as a boolean.
     *
     * @param name property key
     * @return boolean value
     * @exception EPropertyNotFound If the property is not present
     * @exception EBaseException failed to retrieve
     */
    public boolean getBoolean(String name) throws EBaseException {
        String value = get(name);

        if (value == null) {
            logger.trace("Property {} not found", getFullName(name));
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", getName() + "." + name));
        }
        if (value.length() == 0) {
            throw new EPropertyNotDefined(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_NOVALUE", getName() + "." + name));
        }

        if (value.equalsIgnoreCase("true")) {
            return true;
        } else if (value.equalsIgnoreCase("false")) {
            return false;
        } else {
            throw new EBaseException("Invalid boolean value in " + getName() + "." + name + ": " + value);
        }
    }

    /**
     * Retrieves the given property as a boolean.
     *
     * @param name property key
     * @param defval default value
     * @return boolean value
     * @exception EBaseException failed to retrieve
     */
    public boolean getBoolean(String name, boolean defval)
            throws EBaseException {
        boolean val;

        try {
            val = getBoolean(name);
        } catch (EPropertyNotFound e) {
            val = defval;
        } catch (EPropertyNotDefined e) {
            val = defval;
        }

        logger.trace("Getting {}={}", getFullName(name), val);
        return val;
    }

    /**
     * Puts boolean value into the configuration store.
     *
     * @param name property key
     * @param value property value
     */
    public void putBoolean(String name, boolean value) {
        if (value) {
            put(name, "true");
        } else {
            put(name, "false");
        }
    }

    /**
     * Retrieves integer value.
     *
     * @param name The property name
     * @return The property value as an integer
     * @exception EPropertyNotFound If property is not found
     * @exception EBaseException If an internal error occurred
     */
    public int getInteger(String name) throws EBaseException {
        String value = get(name);

        if (value == null) {
            logger.trace("Property {} not found", getFullName(name));
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", getName() + "." + name));
        }
        if (value.length() == 0) {
            throw new EPropertyNotDefined(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_NOVALUE", getName() + "." + name));
        }
        try {
            logger.trace("Getting {}={}", getFullName(name), value);
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new EBaseException("Invalid integer value in " + getName() + "." + name + ": " + value);
        }
    }

    /**
     * Retrieves integer value.
     *
     * @param name property key
     * @param defval default value
     * @return property value
     * @exception EBaseException failed to retrieve value
     */
    public int getInteger(String name, int defval) throws EBaseException {
        int val;

        try {
            val = getInteger(name);
        } catch (EPropertyNotFound e) {
            val = defval;
        } catch (EPropertyNotDefined e) {
            val = defval;
        }
        logger.trace("Getting {}={}", getFullName(name), val);
        return val;
    }

    /**
     * Puts an integer value.
     *
     * @param name property key
     * @param val property value
     */
    public void putInteger(String name, int val) {
        put(name, Integer.toString(val));
    }

    /**
     * Retrieves the given property as a big integer.
     *
     * @param name property key
     * @return property value
     * @exception EPropertyNotFound If property is not found
     * @exception EBaseException failed to retrieve value
     */
    public BigInteger getBigInteger(String name) throws EBaseException {
        String value = get(name);

        if (value == null) {
            logger.trace("Property {} not found", getFullName(name));
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", getName() + "." + name));
        }
        if (value.length() == 0) {
            throw new EPropertyNotDefined(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_NOVALUE", getName() + "." + name));
        }
        try {
            if (value.startsWith("0x") || value.startsWith("0X")) {
                String val = value.substring(2);

                return new BigInteger(val, 16);
            }
            return new BigInteger(value);
        } catch (NumberFormatException e) {
            throw new EBaseException("Invalid BigInteger value in " + getName() + "." + name + ": " + value);
        }
    }

    /**
     * Retrieves the given property as a big integer.
     *
     * @param name property key
     * @param defval default value
     * @return property value
     * @exception EBaseException failed to retrieve value
     */
    public BigInteger getBigInteger(String name, BigInteger defval)
            throws EBaseException {
        BigInteger val;

        try {
            val = getBigInteger(name);
        } catch (EPropertyNotFound e) {
            val = defval;
        } catch (EPropertyNotDefined e) {
            val = defval;
        }
        return val;
    }

    /**
     * Puts a big integer value.
     *
     * @param name property key
     * @param val property value
     */
    public void putBigInteger(String name, BigInteger val) {
        put(name, val.toString());
    }

    /**
     * Creates a nested sub-store with the specified name.
     *
     * @param name The name of the sub-store
     * @return The sub-store created
     */
    public ConfigStore makeSubStore(String name) {
        return makeSubStore(name, ConfigStore.class);
    }

    public <T extends ConfigStore> T makeSubStore(String name, Class<T> clazz) {

        String fullname = getFullName(name);

        /*
         String names=(String)mSource.get(getFullName(PROP_SUBSTORES));

         if (names==null) {
         names=name;
         }
         else {
         names=names+","+name;
         }
         mSource.put(getFullName(PROP_SUBSTORES), name);
         */

        try {
            Constructor<T> constructor = clazz.getDeclaredConstructor(String.class, SimpleProperties.class);
            return constructor.newInstance(fullname, mSource);

        } catch (NoSuchMethodException | InvocationTargetException
                | IllegalAccessException | InstantiationException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Removes a sub store including all properties and sub-stores under this sub-store.
     *
     * @param name substore name
     */
    public void removeSubStore(String name) {
        // this operation is expensive!!!

        Enumeration<String> e = mSource.keys();
        // We only want the keys which match the current substore name
        // without the current substore prefix.  This code works even
        // if mStoreName is null.
        String fullName = getFullName(name);

        while (e.hasMoreElements()) {
            String key = e.nextElement();

            if (key.startsWith(fullName + ".")) {
                ((Hashtable<String, String>) mSource).remove(key);
            }
        }
    }

    /**
     * Retrieves a sub store. A substore contains a list
     * of properties and substores. For example,
     *
     * <pre>{@Code
     * cms.ldap.host=ds.netscape.com
     * cms.ldap.port=389
     * }</pre>
     *
     * "ldap" is a substore in above example. If the
     * substore property itself is set, this method
     * will treat the value as a reference. For example,
     *
     * <pre>{@Code
     * cms.ldap = kms.ldap
     * }</pre>
     *
     * @param name substore name
     * @return substore
     */
    public ConfigStore getSubStore(String name) {
        return getSubStore(name, ConfigStore.class);
    }

    public <T extends ConfigStore> T getSubStore(String name, Class<T> clazz) {

        String fullname = getFullName(name);
        String reference = mSource.get(fullname);

        try {
            Constructor<T> constructor = clazz.getDeclaredConstructor(String.class, SimpleProperties.class);
            return reference == null ? constructor.newInstance(fullname, mSource) : constructor.newInstance(reference, mSource);
        } catch (NoSuchMethodException | InvocationTargetException
                | IllegalAccessException | InstantiationException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Retrieves a list of property names.
     *
     * @return a list of string-based property names
     */
    public Enumeration<String> getPropertyNames() {
        // XXX - this operation is expensive!!!
        Map<String, String> map = getProperties();

        Vector<String> v = new Vector<>();
        for (String name : map.keySet()) {
            int i = name.indexOf('.'); // substores have "."
            if (i >= 0) continue;
            if (v.contains(name)) continue;

            v.addElement(name);
        }

        return v.elements();
    }

    /**
     * Returns a list of sub store names.
     *
     * @return list of substore names
     */
    public Vector<String> getSubStoreNames() {
        // XXX - this operation is expensive!!!
        Map<String, String> map = getProperties();

        Vector<String> v = new Vector<>();
        for (String name : map.keySet()) {
            int i = name.indexOf('.'); // substores have "."
            if (i < 0) continue;

            name = name.substring(0, i);
            if (v.contains(name)) continue;

            v.addElement(name);
        }

        return v;
    }

    /**
     * Retrieves the source configuration store where
     * the properties are stored.
     *
     * @return source configuration store
     */
    public SimpleProperties getSource() {
        return mSource;
    }

    /**
     * For debugging purposes. Prints properties of this
     * substore.
     */
    public void printProperties() {
        Enumeration<String> keys = mSource.keys();

        while (keys.hasMoreElements()) {
            String key = keys.nextElement();

            if (mStoreName == null) {
                System.out.println(key);
            } else {
                if (key.startsWith(mStoreName))
                    System.out.println(key);
            }
        }
    }

    /**
     * Converts the substore parameters.
     *
     * @param name property name
     * @return fill property name
     */
    protected String getFullName(String name) {
        return mStoreName == null ? name : mStoreName + "." + name;
    }

    /**
     * Cloning of property configuration store.
     *
     * @return a new configuration store
     */
    @Override
    public Object clone() {
        try {
            ConfigStore that = (ConfigStore) super.clone();

            mStoreName = getName();
            mSource = new SimpleProperties();
            Enumeration<String> subs = getSubStoreNames().elements();

            while (subs.hasMoreElements()) {
                String name = subs.nextElement();

                ConfigStore sub = getSubStore(name, ConfigStore.class);
                ConfigStore newSub = that.makeSubStore(sub.getName());

                Enumeration<String> props = sub.getPropertyNames();

                while (props.hasMoreElements()) {
                    String n = props.nextElement();

                    try {
                        newSub.putString(n,
                                sub.getString(n));
                    } catch (EBaseException ex) {
                    }
                }
            }
            return that;
        } catch (CloneNotSupportedException e) {
            return null;
        }

    }
}

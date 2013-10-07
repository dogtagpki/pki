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
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

import org.mozilla.jss.util.Base64OutputStream;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotDefined;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISourceConfigStore;
import com.netscape.cmsutil.util.Utils;

/**
 * A class represents a in-memory configuration store.
 * Note this class takes advantage of the recursive nature of
 * property names. The current property prefix is kept in
 * mStoreName and the mSource usually points back to another
 * occurance of the same PropConfigStore, with longer mStoreName. IE
 *
 * <PRE>
 * 	cms.ca0.http.service0 -> mSource=PropConfigStore ->
 * 		cms.ca0.http -> mSource=PropConfigStore ->
 * 			cms.ca0 -> mSource=PropConfigStore ->
 * 					cms -> mSource=SourceConfigStore -> Properties
 * </PRE>
 *
 * The chain ends when the store name is reduced down to it's original
 * value.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class PropConfigStore implements IConfigStore, Cloneable {

    /**
     *
     */
    private static final long serialVersionUID = 4714108964096659077L;

    protected static final String PROP_SUBSTORES = "substores";

    /**
     * The name of this substore
     */
    protected String mStoreName = null;

    /**
     * The source data for this substore
     */
    protected ISourceConfigStore mSource = null;

    private static String mDebugType = "CS.cfg";

    /**
     * Constructs a property configuration store. This must
     * be a brand new store without properties. The subclass
     * must be a ISourceConfigStore.
     * <P>
     *
     * @param storeName property store name
     * @exception EBaseException failed to create configuration
     */
    public PropConfigStore(String storeName) {
        mSource = new SourceConfigStore();
        mStoreName = storeName;
    }

    /**
     * Constructs a configuration store. The constructor is
     * a helper class for substores. Source is the one
     * that stores all the parameters. Each substore only
     * store a substore name, and a reference to the source.
     * <P>
     *
     * @param storeName store name
     * @param prop list of properties
     * @exception EBaseException failed to create configuration
     */
    protected PropConfigStore(String name, ISourceConfigStore source) {
        mStoreName = name;
        mSource = source;
    }

    /**
     * Returns the name of this store.
     * <P>
     *
     * @return store name
     */
    public String getName() {
        return mStoreName;
    }

    /**
     * Retrieves a property from the configuration file.
     * <P>
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
     * <P>
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
     * <P>
     *
     * @param name property name
     * @param value property value
     */
    public String put(String name, String value) {
        return mSource.put(getFullName(name), value);
    }

    /**
     * Removes a property from the configuration file.
     *
     * @param name property name
     */
    public void remove(String name) {
        ((SourceConfigStore) mSource).remove(getFullName(name));
    }

    /**
     * Returns an enumeration of the config store's keys, hidding the store
     * name.
     *
     * @see java.util.Hashtable#elements
     * @see java.util.Enumeration
     */
    public Enumeration<String> keys() {
        Hashtable<String, String> h = new Hashtable<String, String>();
        enumerate(h);
        return h.keys();
    }

    /**
     * Retrieves lexicographically sorted properties as a map.
     *
     * @return map
     */
    public Map<String, String> getProperties() {
        Map<String, String> map = new TreeMap<String, String>();
        enumerate(map);
        return map;
    }

    /**
     * Return the number of items in this substore
     */
    public int size() {
        Hashtable<String, String> h = new Hashtable<String, String>();
        enumerate(h);
        return h.size();
    }

    /**
     * Fills the given map with all key/value pairs in the current
     * config store, removing the config store name prefix
     * <P>
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
     * @param header optional header information to be saved
     */
    public synchronized void save(OutputStream out, String header) {
        mSource.save(out, header);
    }

    /**
     * Retrieves a property value.
     *
     * @param name property key
     * @return property value
     * @exception EBaseException failed to retrieve value
     */
    public String getString(String name) throws EBaseException {
        String str = get(name);

        if (str == null) {
            CMS.traceHashKey(mDebugType, getFullName(name), "<notpresent>");
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", getName() + "." + name));
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
        CMS.traceHashKey(mDebugType, getFullName(name), ret);
        return ret;
    }

    /**
     * Retrieves a String from the configuration file.
     * <P>
     *
     * @param name property name
     * @param defval the default object to return if name does not exist
     * @return property value
     */
    public String getString(String name, String defval) throws EBaseException {
        String val;

        try {
            val = getString(name);
        } catch (EPropertyNotFound e) {
            val = defval;
        }
        CMS.traceHashKey(mDebugType, getFullName(name), val, defval);
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
     * <P>
     *
     * @param name property name
     * @exception IllegalArgumentException if name is not set or is null.
     *
     * @return property value
     */
    public byte[] getByteArray(String name) throws EBaseException {
        byte[] arr = getByteArray(name, new byte[0]);

        if (arr.length == 0) {
            CMS.traceHashKey(mDebugType, getFullName(name), "<notpresent>");
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", getName() + "." + name));
        }
        return arr;
    }

    /**
     * Retrieves a byte array from the configuration file.
     * <P>
     *
     * @param name property name
     * @param defval the default byte array to return if name does
     *            not exist
     *
     * @return property value
     */
    public byte[] getByteArray(String name, byte defval[])
            throws EBaseException {
        String str = get(name);

        if (str == null || str.length() == 0) {
            CMS.traceHashKey(mDebugType, getFullName(name),
                    "<notpresent>", "<bytearray>");
            return defval;
        } else {
            CMS.traceHashKey(mDebugType, getFullName(name),
                    "<bytearray>", "<bytearray>");
            return Utils.base64decode(str);
        }
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
            System.out.println("Warning: base-64 encoding of configuration " +
                    "information failed");
        }
    }

    /**
     * Retrieves boolean-based property value.
     *
     * @param name property key
     * @return boolean value
     * @exception EBaseException failed to retrieve
     */
    public boolean getBoolean(String name) throws EBaseException {
        String value = get(name);

        if (value == null) {
            CMS.traceHashKey(mDebugType, getFullName(name), "<notpresent>");
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
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY_1", getName() + "." + name,
                    "boolean", "\"true\" or \"false\""));
        }
    }

    /**
     * Retrieves boolean-based property value.
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
        CMS.traceHashKey(mDebugType, getFullName(name),
                val ? "true" : "false", defval ? "true" : "false");
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
     * @param name property key
     * @return property value
     * @exception EBaseException failed to retrieve value
     */
    public int getInteger(String name) throws EBaseException {
        String value = get(name);

        if (value == null) {
            CMS.traceHashKey(mDebugType, getFullName(name), "<notpresent>");
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", getName() + "." + name));
        }
        if (value.length() == 0) {
            throw new EPropertyNotDefined(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_NOVALUE", getName() + "." + name));
        }
        try {
            CMS.traceHashKey(mDebugType, getFullName(name), value);
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY_1", getName() + "." + name, "int",
                    "number"));
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
        CMS.traceHashKey(mDebugType, getFullName(name),
                "" + val, "" + defval);
        return val;
    }

    /**
     * Puts an integer value.
     *
     * @param name property key
     * @param val property value
     * @exception EBaseException failed to retrieve value
     */
    public void putInteger(String name, int val) {
        put(name, Integer.toString(val));
    }

    /**
     * Retrieves big integer value.
     *
     * @param name property key
     * @return property value
     * @exception EBaseException failed to retrieve value
     */
    public BigInteger getBigInteger(String name) throws EBaseException {
        String value = get(name);

        if (value == null) {
            CMS.traceHashKey(mDebugType, getFullName(name), "<notpresent>");
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
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY_1", getName() + "." + name,
                    "BigInteger", "number"));
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
     * @param val default value
     */
    public void putBigInteger(String name, BigInteger val) {
        put(name, val.toString());
    }

    /**
     * Creates a new sub store.
     * <P>
     *
     * @param name substore name
     * @return substore
     */
    public IConfigStore makeSubStore(String name) {

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
        return new PropConfigStore(getFullName(name), mSource);
    }

    /**
     * Removes a sub store.
     * <p>
     *
     * @param name substore name
     */
    @SuppressWarnings("unchecked")
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
     * <PRE>
     *    cms.ldap.host=ds.netscape.com
     *    cms.ldap.port=389
     * </PRE>
     *
     * "ldap" is a substore in above example. If the
     * substore property itself is set, this method
     * will treat the value as a reference. For example,
     *
     * <PRE>
     * cms.ldap = kms.ldap
     * </PRE>
     * <P>
     *
     * @param name substore name
     * @return substore
     */
    public IConfigStore getSubStore(String name) {
        String fullname = getFullName(name);
        String reference = mSource.get(fullname);

        if (reference == null) {
            PropConfigStore ps = new PropConfigStore(fullname, mSource);

            return ps;
        } else {
            PropConfigStore ps = new PropConfigStore(reference, mSource);

            return ps;
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

        Vector<String> v = new Vector<String>();
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
     * <P>
     *
     * @return list of substore names
     */
    public Enumeration<String> getSubStoreNames() {
        // XXX - this operation is expensive!!!
        Map<String, String> map = getProperties();

        Vector<String> v = new Vector<String>();
        for (String name : map.keySet()) {
            int i = name.indexOf('.'); // substores have "."
            if (i < 0) continue;

            name = name.substring(0, i);
            if (v.contains(name)) continue;

            v.addElement(name);
        }

        return v.elements();
    }

    /**
     * Retrieves the source configuration store where
     * the properties are stored.
     * <P>
     *
     * @return source configuration store
     */
    public ISourceConfigStore getSourceConfigStore() {
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
    private String getFullName(String name) {
        if (mStoreName == null)
            return name;
        else
            return mStoreName + "." + name;
    }

    /**
     * Cloning of property configuration store.
     *
     * @return a new configuration store
     */
    public Object clone() {
        try {
            PropConfigStore that = (PropConfigStore) super.clone();

            mStoreName = getName();
            mSource = new SourceConfigStore();
            Enumeration<String> subs = getSubStoreNames();

            while (subs.hasMoreElements()) {
                String name = subs.nextElement();

                IConfigStore sub = getSubStore(name);
                IConfigStore newSub = that.makeSubStore(sub.getName());

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

    /**
     * Commits properties into the file.
     *
     * @param createBackup true if create backup
     * @exception EBaseException failed to commit properties
     */
    public void commit(boolean createBackup) throws EBaseException {
    }
}

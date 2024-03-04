/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.preferences;

import java.util.*;
import java.io.*;
import com.netscape.management.client.util.*;

/**
 * Provides access to a set of preference settings.
 * Each setting is defined by a name and value pair,
 * for example: "name" = "Joe"
 *
 * Persistant storage of preference data is provided by
 * input and output streams which are implemented by
 * subclasses of Preferences.
 *
 * @author  ahakim@netscape.com
 * @see PreferenceManager
 */
public abstract class Preferences extends Properties {
    private boolean _isLoaded = false;
    private boolean _isDirty = false;

    /**
     */
    public String toString() {
        if (!_isLoaded)
            load();
        return super.toString();
    }

    /**
      * Returns String preference value.
     * null is returned if it does not exist.
     *
     * @param name preference name
      */
    public String getString(String name) {
        if (!_isLoaded)
            load();

        return (String) super.get(name);
    }

    /**
      * Returns String preference value.
     * defaultValue is returned if it does not exist.
     *
     * @param name preference name
     * @param defaultValue value to return if name does not exist
      */
    public String getString(String name, String defaultValue) {
        String s = getString(name);
        if (s == null)
            return defaultValue;
        return s;
    }

    /**
      * Returns integer preference value.
     * NumberFormatException is thrown if name does not exist
     * or if the value is not a valid integer.
     *
     * @param name preference name
      */
    public int getInt(String name) throws NumberFormatException {
        String s = getString(name);
        try {
            Integer i = Integer.valueOf(s);
            return i.intValue();
        } catch (NumberFormatException e) {}
        throw new NumberFormatException(name + "=" + s);
    }

    /**
      * Returns integer preference value.
     * The defaultValue is returned if the name does not exist
     * or if the value is not a valid integer.
     *
     * @param name preference name
     * @param defaultValue value to return if name does not exist
      */
    public int getInt(String name, int defaultValue) {
        String s = getString(name);
        if (s != null)
            try {
                Integer i = Integer.valueOf(s);
                return i.intValue();
            } catch (NumberFormatException e) {}

        return defaultValue;
    }

    /**
      * Returns boolean preference value.
     * false is returned if the name does not exist
     * or if the value is not a valid integer.
     *
     * @param name preference name
      */
    public boolean getBoolean(String name) {
        return getBoolean(name, false);
    }

    /**
      * Returns a boolean preference value.
     * false is returned if the name does not exist
     * or if the value is not a valid integer.
     *
     * @param name preference name
     * @param defaultValue value to return if name does not exist
      */
    public boolean getBoolean(String name, boolean defaultValue) {
        boolean result = defaultValue;
        String s = getString(name);
        if (s != null) {
            Boolean b = Boolean.valueOf(s);
            result = b.booleanValue();
        }
        return result;
    }

    /**
      * Sets String preference value.
     *
     * @param name preference name
     * @param value preference value
      */
    public void set(String name, String value) {
        put(name, value);
        _isDirty = true;
    }

    /**
      * Sets integer preference value.
     *
     * @param name preference name
     * @param value preference value
      */
    public void set(String name, int value) {
        put(name, String.valueOf(value));
        _isDirty = true;
    }

    /**
      * Sets boolean preference value.
     *
     * @param name preference name
     * @param value preference value
      */
    public void set(String name, boolean value) {
        put(name, String.valueOf(value));
        _isDirty = true;
    }

    /**
      * Returns an Enumeration of preference names.
      */
    public Enumeration getNames() {
        if (!_isLoaded)
            load();
        return propertyNames();
    }

    /**
      * Loads preference settings from the persistant store.
      */
    public synchronized void load() {
        InputStream inStream = getInputStream();
        if (inStream != null)
            try {
                load(inStream);
                _isLoaded = true;
            } catch (IOException e) {
                Debug.println("Cannot load preferences: " + e);
            }
    }

    /**
      * Saves preference settings to the persistant store.
      */
    public synchronized void save() {
        if (_isDirty == false)
            return;

        OutputStream outStream = getOutputStream();
        if (outStream != null) {
            save(outStream, "");
            try {
                outStream.flush();
                _isDirty = false;
            } catch (IOException e) {
                Debug.println("Cannot save preferences: " + e);
            }
        }
    }

    /**
      * Clears preference settings in memory.
      */
    public void clear() {
        super.clear();
        _isDirty = true;
    }

    /**
      * Clears preference settings from the persistant store.
      */
    public abstract void delete();

    /**
     * Tests if this preferences group has no data
     */
    public boolean isEmpty() {
        if (!_isLoaded)
            load();
        return super.isEmpty();
    }

    /**
      * Tests if this preferences group has data that is not saved
      */
    public boolean isDirty() {
        return _isDirty;
    }

    /**
      * Returns the InputStream to read from the persistant store.
      */
    abstract protected InputStream getInputStream();

    /**
     * Returns the OutputStream to write to the persistant store.
     */
    abstract protected OutputStream getOutputStream();
}

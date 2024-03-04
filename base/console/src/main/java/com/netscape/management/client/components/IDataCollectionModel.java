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
package com.netscape.management.client.components;
/*
=====================================================================

        WizardSequenceManager.java

        Created by Claude Duguay
        Copyright (c) 1998

=====================================================================
*/

import javax.swing.event.ChangeListener;

/**
 * A Data Colection Model stores data as its being collected
 * and notifies any Change listeners when the data changes.
 * Values may be added, removed or looked up.
 */
public interface IDataCollectionModel
{

    /**
     * Tests if the specified key is valid
     *
     * @param key possible key
     * @return true if the specified key is valid; false otherwise
     *
     */
    public boolean containsKey(String key);

    /**
     * Returns the value to which the specified key is mapped to
     *
     * @param key possible key
     * @return the value to which the key is mapped
     *
     */
    public Object getValue(String key);

    /**
     * Returns the value to which the specified key is mapped
     * defaultValue will be returned if an invalid key is specified
     *
     * @param key possible key
     * @param defaultValue value to return if a invalid key is supplied
     * @return the value to which the key is maapped to, or defaultValue if key is invalid
     *
     */
    public Object getValue(String key, Object defaultValue);

    /**
     * Maps the specified key to specified value.
     * The value can be retrieved by calling the get method with a key that is equal to the original key.
     *
     * @param key possible key
     * @param value the value
     */
    public void setValue(String key, Object value);

    /**
     * Removes the key (and its corresponding value).
     *
     * @param key possible key
     */
    public void removeValue(String key);

    /**
     * Add a change listener.
     *
     * @param listener the listener
     */
    public void addChangeListener(ChangeListener listener);

    /**
     * Remove a change listener.
     *
     * @param listener the listener
     */
    public void removeChangeListener(ChangeListener listener);
}

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

        PropertyDataModel.java

        Created by Claude Duguay
        Copyright (c) 1998

=====================================================================
*/

import java.util.Vector;
import java.util.Properties;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * Default data collection model
 *
 * @see Wizard
 * @see DataCollectionModel
 */
public class WizardDataCollectionModel extends Properties
        implements IDataCollectionModel
{
    protected Vector listeners = new Vector();


    /**
     * Create a data collection model to be shared by
     * all wizard pages
     *
     */
    public WizardDataCollectionModel()
    {
        super();
    }

    /**
     * Tests if the specified object is a key in this data collection model.
     *
     * @param key possible key
     */
    public boolean containsKey(String key)
    {
        return super.containsKey(key);
    }

    /**
     * Returns the value to which the specified key is mapped in
     * this data collection model
     *
     * @param key possible key
     * @return the value to which the key is mapped in this data collection model; null if key does not mapped to any value.
     *
     */
    public Object getValue(String key)
    {
        return get(key);
    }

    /**
     * Returns the value value to which the specified key is mapped
     * in this data collection model.  Specified default value will
     * be returned if key does not map to any value.
     *
     * @param key a key in the data collection model.
     * @param defaultValue default value to return if key is not mapped to any value
     * @return the value to which the key is mapped in this data collection model; defaultValue if key does not mapped to any value in this data collection.
     *
     */
    public Object getValue(String key, Object defaultValue)
    {
        if (containsKey(key)) return get(key);
        else return defaultValue;
    }

    /**
     * Maps the specified key to the specified value.
     * Neither the key nor the value can be null.
     *
     * The value can be retrieved by calling the getValue method with a key
     * that is equal to the original key.
     *
     * @param key the key.
     * @param value the value.
     *
     */
    public void setValue(String key, Object value)
    {
        put(key, value);
        fireChangeEvent();
    }

    /**
     * Removes the key (and its corresponding value) from this data collection model
     *
     * @param key the key that needs to be removed.
     */
    public void removeValue(String key)
    {
        remove(key);
        fireChangeEvent();
    }

    /**
     * Add a data collection change listener
     *
     * @param listener listener to add
     */
    public void addChangeListener(ChangeListener listener)
    {
        listeners.addElement(listener);
    }

    /**
     * Remove a data collection change listener
     *
     * @param listener listener to remove
     */
    public void removeChangeListener(ChangeListener listener)
    {
        listeners.removeElement(listener);
    }

    /**
     * Notify each listener that a change has occure
     *
     *
     */
    public void fireChangeEvent()
    {
        Vector list = (Vector)listeners.clone();
        ChangeEvent event = new ChangeEvent(this);
        ChangeListener listener;
        for (int i = 0; i < list.size(); i++)
            {
                listener = (ChangeListener)list.elementAt(i);
                listener.stateChanged(event);
            }
    }

}

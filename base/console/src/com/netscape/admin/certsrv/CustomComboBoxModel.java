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
package com.netscape.admin.certsrv;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

/**
 * Custom Combo Box Model
 * Let you specify an icon and title to be displayed.
 *
 * @author  jpanchen
 * @version $Revision$, $Date$
 * @see     com.netscape.admin.certsrv
 * @see     CustomComboBox
 */
class CustomComboBoxModel extends AbstractListModel implements ComboBoxModel {
    
    /*==========================================================
     * constructors
     *==========================================================*/    
    public CustomComboBoxModel() {
        _cache = new Vector();
        _index = new Vector();
    }

	/*==========================================================
	 * public methods
     *==========================================================*/
     
    /**
     * set selected item
     * DO NOT USE!!!
     * use JComboBox.setSelectedIndex()
     */
    public void setSelectedItem(Object anObject) {
        _currentValue = anObject;
        fireContentsChanged(this,-1,-1);
    }

    /**
     * Get selected Item.
     * DO NOT USE !!!
     * use JComboBox.getItemAt(JComboBox.getSelectedIndex())
     */
    public Object getSelectedItem() {
        return _currentValue;
    }

    /**
     * Return size
     * @return size
     */
    public int getSize() {
        return _cache.size();
    }

    /**
     * Retrieve element at index position
     * @param index location
     * @Object Hashtable obejct with "icon" and "title" field
     */
    public Object getElementAt(int index) {
        try {
            return _cache.elementAt(index);
        } catch(ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }
    
    /**
     * set default icon
     * @param icon new icon to be used
     */
    public void setIcon(ImageIcon icon) {
        _icon = icon;
    }

    /**
     * Add new list entry into model
     * @param icon new icon associated
     * @param title text associated
     */
    public void addItem(ImageIcon icon, String title, Object data) {
        Hashtable newItem = new Hashtable();
        newItem.put(SELECTION_ICON,icon);
        newItem.put(SELECTION_TITLE, title);
        newItem.put(SELECTION_DATA, data);
        _cache.addElement(newItem);
        _index.addElement(title.toUpperCase());
    }    
    
    /**
     * Add new list entry into model
     * @param icon new icon associated
     * @param title text associated
     */
    public void addItem(ImageIcon icon, String title) {
        Hashtable newItem = new Hashtable();
        newItem.put(SELECTION_ICON,icon);
        newItem.put(SELECTION_TITLE, title);
        _cache.addElement(newItem);
        _index.addElement(title.toUpperCase());
    }
    
    /**
     * Add new list entry into model.
     * Default icon used
     * @param title text associated
     */
    public void addItem(String title) {
        Hashtable newItem = new Hashtable();
        newItem.put(SELECTION_ICON,_icon);
        newItem.put(SELECTION_TITLE, title);
        _cache.addElement(newItem);
        _index.addElement(title.toUpperCase());
    }
    
    /**
     * Remove all entries from the model
     */
    public void removeAll() {
        _cache.removeAllElements();
    }
    
    /**
     * Remove specific entry from the model
     * @param key key string associated with the entry
     */
    public void removeEntry(String key) {
        int x = _index.indexOf(key.toUpperCase());
        if ((x != -1) && (x < _cache.size()) ) {
            _cache.removeElementAt(x);
            _index.removeElementAt(x);
        }
    }
    
    /*==========================================================
     * variables
     *==========================================================*/
     
    public static final String SELECTION_TITLE = "title";
    public static final String SELECTION_ICON = "icon";
    public static final String SELECTION_DATA = "data";
    
    private Object _currentValue;
    private Vector _cache;
    private Vector _index;
    private ImageIcon _icon;
}

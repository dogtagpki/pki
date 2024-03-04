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
package com.netscape.management.client.topology;

/**
 * each individual topology node will have a right hand side conifguration panel.
 * Node Data is each attribute of the node. For example, version, installation date, etcc.
 * This data structure is used to represent the attribute information. For example,
 * the control type or whether the attribute is editable or not.
 */
public class NodeData {
    String _id;
    String _name;
    Object _value;
    boolean _isEditable;
    boolean _is7bit = false;
    boolean isMultiline = true;

    /**
     * Constructs NodeData object
     *
     * @param id unique id for this field
     * @param name display name, shows up as
     * @param value initial value for this field
     * @param isEditable true if field can be edited through the UI
     * @param is7bit true if field can only accept 7-bit input
     */
    public NodeData(String id, String name, Object value,
            boolean isEditable, boolean is7bit) {
        _id = id;
        _name = name;
        _value = value;
        _isEditable = isEditable;
        _is7bit = is7bit;
    }

    /**
      * Constructs NodeData object
      *
      * @param id unique id for this field
      * @param name display name, shows up as
      * @param value initial value for this field
      * @param isEditable true if field can be edited through the UI
      */
    public NodeData(String id, String name, Object value,
            boolean isEditable) {
        this(id, name, value, isEditable, false);
    }

    /**
      * Constructs a non-editable object
      *
      * @param id unique string id
      * @param name display name, shows up as
      * @param value initial value
      */
    public NodeData(String id, String name, Object value) {
        this(id, name, value, false);
    }

    /**
      * Constructs a non-editable object with no display name
      *
      * @param id unique id
      * @param value initial value
      */
    public NodeData(String id, Object value) {
        this(id, "", value, false);
    }

    /**
      * @return string ID
      */
    public String getID() {
        return _id;
    }

    /**
      * @return display name
      */
    public String getName() {
        return _name;
    }

    /**
      * @return data value
      */
    public Object getValue() {
        return _value;
    }

    /**
      * @param value new data value
      */
    public void setValue(Object value) {
        _value = value;
    }

    /**
      * @return true if editable through UI
      */
    public boolean isEditable() {
        return _isEditable;
    }

    /**
      * @return true if field can only accept 7-bit input
      */
    public boolean is7Bit() {
        return _is7bit;
    }

    /**
      * @param is7Bit true if field can only accept 7-bit input
      */
    public void set7Bit(boolean is7Bit) {
        _is7bit = is7Bit;
    }

    /**
      * @return contents of this field
      */
    public String toString() {
        return "ID=" + _id + " " + "Name=" + _name + " " + "Value=" +
                _value + " " + "IsEditable=" + _isEditable;
    }
}

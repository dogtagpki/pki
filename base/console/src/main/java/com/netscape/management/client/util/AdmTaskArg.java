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
package com.netscape.management.client.util;


/**
 * Argument (name-value pair) data structure for AdminTask
 *
 * @author  yjh
 * @see AdmTask
 */
public class AdmTaskArg extends Object {
    private String _name;
    private String _val;

    /**
     * Constructor to build a name-value pair
     * @param name new name
     * @param val new value
     */
    public AdmTaskArg(String name, String val) {
        _name = name;
        _val = val;
    };

    /**
     * Determine whether two AdmTaskArgs are equal
     *
     * @param obj the other AdmTaskArg
     */
    public boolean equals(Object obj) {
        AdmTaskArg arg = (AdmTaskArg) obj;
        return ((_name.equals(arg.name())) && (_val.equals(arg.val())));
    };

    /**
     * Convert the content to a printable string presentation
     *
     */
    public String toString() {
        String resultString;
        resultString = "(" + _name + ", " + _val + ")";
        return resultString;
    };

    /**
     * Get the name of this argument.
     *
     * @return name of the argument
     */
    public String name() {
        return _name;
    };

    /**
     * Get the value of this argument.
     *
     * @return value of the argument
     */
    public String val() {
        return _val;
    };

    /**
     * Set the name of this argument.
     *
     * @apram new name of the argument
     */
    public void name(String newName) {
        _name = newName;
    };

    /**
     * Set the value of this argument.
     *
     * @param new value of the argument
     */
    public void val(String newValue) {
        _val = newValue;
    };

};


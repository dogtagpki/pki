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
package com.netscape.certsrv.template;

import java.util.Enumeration;
import java.util.Hashtable;

/**
 * This class represents a set of arguments.
 * Unlike ArgList, this set of arguments is 
 * not ordered.
 * <p>
 * Each argument in the set is tagged with
 * a name (key).
 * <p>
 * 
 * @version $Revision$, $Date$
 */
public class ArgSet implements IArgValue {
    private Hashtable<String, IArgValue> mArgs = new Hashtable<String, IArgValue>();

    /**
     * Returns a list of argument names.
     *
     * @return list of argument names
     */
    public Enumeration<String> getNames() {
        return mArgs.keys();
    }

    /**
     * Sets string argument into the set with the given name.
     *
     * @param name argument name
     * @param arg argument in string
     */
    public void set(String name, String arg) {
        mArgs.put(name, new ArgString (arg));
    }

    /**
     * Sets argument into the set with the given name.
     *
     * @param name argument name
     * @param arg argument value
     */
    public void set(String name, IArgValue arg) {
        mArgs.put(name, arg);
    }

    /**
     * Retrieves argument from the set.
     *
     * @param name argument name
     * @return argument value
     */
    public IArgValue get(String name) {
        return (IArgValue) mArgs.get(name);
    }
}

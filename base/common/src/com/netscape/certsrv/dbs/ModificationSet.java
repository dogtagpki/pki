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
package com.netscape.certsrv.dbs;

import java.util.Enumeration;
import java.util.Vector;

/**
 * A class represents a modification set. A modification
 * set contains zero or more modifications.
 *
 * @version $Revision$, $Date$
 */
public class ModificationSet {

    /**
     * A list of modifications
     */
    private Vector<Modification> mods = new Vector<Modification>();

    /**
     * Constructs modification set.
     */
    public ModificationSet() {
    }

    /**
     * Adds modification to this set.
     *
     * @param name attribute name
     * @param op modification operation
     * @param value attribute value
     */
    public void add(String name, int op, Object value) {
        mods.addElement(new Modification(name, op, value));
    }

    /**
     * Retrieves a list of modifications.
     *
     * @return a list of Modifications
     */
    public Enumeration<Modification> getModifications() {
        return mods.elements();
    }
}

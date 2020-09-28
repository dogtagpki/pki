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
package com.netscape.certsrv.base;

import java.io.Serializable;
import java.util.Enumeration;

/**
 * This interface defines the abstraction for the generic collection
 * of attributes indexed by string names.
 * Set of cooperating implementations of this interface may exploit
 * dot-separated attribute names to provide seamless access to the
 * attributes of attribute value which also implements AttrSet
 * interface as if it was direct attribute of the container
 * E.g., ((AttrSet)container.get("x")).get("y") is equivalent to
 * container.get("x.y");
 * <p>
 *
 * @version $Revision$, $Date$
 **/
public interface IAttrSet extends Serializable {

    /**
     * Sets an attribute value within this AttrSet.
     *
     * @param name the name of the attribute
     * @param obj the attribute object.
     * @exception EBaseException on attribute handling errors.
     */
    public void set(String name, Object obj) throws EBaseException;

    /**
     * Gets an attribute value.
     *
     * @param name the name of the attribute to return.
     * @exception EBaseException on attribute handling errors.
     */
    public Object get(String name) throws EBaseException;

    /**
     * Deletes an attribute value from this AttrSet.
     *
     * @param name the name of the attribute to delete.
     * @exception EBaseException on attribute handling errors.
     */
    public void delete(String name) throws EBaseException;

    /**
     * Returns an enumeration of the names of the attributes existing within
     * this AttrSet.
     *
     * @return an enumeration of the attribute names.
     */
    public Enumeration<String> getElements();
}

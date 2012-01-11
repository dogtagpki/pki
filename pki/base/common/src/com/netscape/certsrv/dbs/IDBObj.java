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

import com.netscape.certsrv.base.IAttrSet;

/**
 * An interface represents a database object
 * that is serializable.
 * 
 * @version $Revision$, $Date$
 */
public interface IDBObj extends IAttrSet {

    /**
     * Returns a list of serializable attribute
     * names. This method should return the
     * attribute name even if there is no attribute
     * value for the attribute.
     * 
     * @return a list of serializable attribute names
     */
    public Enumeration<String> getSerializableAttrNames();
}

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
package com.netscape.certsrv.profile;


/**
 * This interface represents a profile context which
 * stores system-wide and user-provided information for
 * assisting request creation.
 *
 * @version $Revision$, $Date$
 */
public interface IProfileContext {

    /**
     * Sets a value into the context.
     *
     * @param name property name
     * @param value property value
     */
    public void set(String name, String value);

    /**
     * Retrieves a value from the context.
     *
     * @param name property name
     * @return property value
     */
    public String get(String name);
}

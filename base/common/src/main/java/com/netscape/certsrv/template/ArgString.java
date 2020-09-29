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

/**
 * This class represents a string-based argument.
 *
 * @version $Revision$, $Date$
 */
public class ArgString implements IArgValue {
    private String mValue = null;

    /**
     * Constructs a string-based argument value.
     *
     * @param value argument value
     */
    public ArgString(String value) {
        mValue = value;
    }

    /**
     * Returns the argument value.
     *
     * @return argument value
     */
    public String getValue() {
        return mValue;
    }
}

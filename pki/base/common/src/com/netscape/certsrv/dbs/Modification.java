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


import java.util.*;


/**
 * A class represents a modification. This is used by the
 * database (dbs) framework for modification operations.
 * It specifices the modification type and values.
 *
 * @version $Revision$, $Date$
 */
public class Modification {

    /**
     * Add new value.
     */
    public static final int MOD_ADD = 0;

    /**
     * Deletes old value.
     */
    public static final int MOD_DELETE = 1;

    /**
     * Replace old value.
     */
    public static final int MOD_REPLACE = 2;

    private String mName = null;
    private int mOp;
    private Object mValue = null;

    /**
     * Constructs a role modification.
     *
     * @param name attribute name
     * @param op attribute operation (i.e. MOD_ADD, MOD_DELETE, or MOD_REPLACE)
     * @param value attribute value
     */
    public Modification(String name, int op, Object value) {
        mName = name;
        mOp = op;
        mValue = value;
    }

    /**
     * Retrieves attribute name.
     *
     * @return attribute name
     */
    public String getName() {
        return mName;
    }

    /**
     * Retrieves modification operation type.
     *
     * @return modification type
     */
    public int getOp() {
        return mOp;
    }

    /**
     * Retrieves attribute value.
     *
     * @return attribute value
     */
    public Object getValue() {
        return mValue;
    }
}

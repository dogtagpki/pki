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

import java.util.*;

/**
 * This class represents a list of arguments
 * that will be returned to the end-user via
 * the template framework.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class ArgList implements IArgValue {

    private Vector mList = new Vector();

    /**
     * Constructs a argument list object.
     */
    public ArgList() {
    }

    /**
     * Adds an argument to the list.
     *
     * @param arg argument to be added
     */
    public void add(IArgValue arg) {
        mList.addElement(arg);
    }

    /** 
     * Returns the number of arguments in the list.
     *
     * @return size of the list
     */
    public int size() {
        return mList.size();
    }

    /**
     * Returns the argument at the given position
     * Position starts from 0.
     *
     * @param pos position
     * @return argument
     */
    public IArgValue get(int pos) {
        return (IArgValue) mList.elementAt(pos);
    }
}

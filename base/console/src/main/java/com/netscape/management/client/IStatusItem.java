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
package com.netscape.management.client;

import java.awt.*;

/**
 * Defines the minimum set of properties for a status item
 * that can appear on the Console's status bar.
 */
public interface IStatusItem {
    public static final String LEFTFIRST = "LF";
    public static final String LEFTEDGE = LEFTFIRST;
    public static final String LEFT = "L";
    public static final String CENTERFIRST = "CF";
    public static final String CENTER = "C";
    public static final String RIGHTFIRST = "RF";
    public static final String RIGHT = "R";

    /**
     * Returns identifer for this item.  The item is
     * used internally for tracking and reference purposes.
     *
     * @return a string ID
     */
    public abstract String getID();

    /**
        * A Component to render UI for this object.
        *
        * @return Component that renders UI for this object.
        */
    public abstract Component getComponent();

    /**
     * Sets new state for this status item.  Its value
     * varies based on the class that implements this interface.
     * The state will be a more specific type than Object.
     *
     * @param state		object representing new state for status item
     */
    public abstract void setState(Object state);

    /**
     * Sets new state for this status item.  Its value
     * varies based on the class that implements this interface.
     * The state will be a more specific type than Object.
     *
     * @return state of this status item
     */
    public abstract Object getState();
}

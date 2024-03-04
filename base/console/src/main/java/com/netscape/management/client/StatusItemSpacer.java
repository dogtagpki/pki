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
import javax.swing.*;

/**
 * Implements a status item that takes up a fixed amount of
 * horizontal space on the status bar.
 *
 * @see IStatusItem
 */
public class StatusItemSpacer implements IStatusItem {
    public static final int HORIZONTAL = 0;
    public static final int VERTICAL = 1;
    public static final int DEFAULT_SIZE = 6;
    protected String _id = null;
    protected int _orientation = HORIZONTAL;
    protected int _size;

    /**
     * Creates status component, orientation = horizontal, size = DEFAULT_SIZE
     */
    public StatusItemSpacer(String id) {
        setID(id);
        _orientation = HORIZONTAL;
        _size = DEFAULT_SIZE;
    }

    /**
     * Creates status component, orientation = horizontal
     */
    public StatusItemSpacer(String id, int size) {
        setID(id);
        _orientation = HORIZONTAL;
        _size = size;
    }

    /**
     * Creates status component with specified orientation and size.
     */
    public StatusItemSpacer(String id, int orientation, int size) {
        setID(id);
        _orientation = orientation;
        _size = size;
    }

    /**
     * Returns the associated view Component.
     */
    public Component getComponent() {
        if (_orientation == HORIZONTAL)
            return Box.createHorizontalStrut(_size);
        else
            return Box.createVerticalStrut(_size);
    }

    /**
     * Returns unique, language independant ID.
     */
    public String getID() {
        return _id;
    }

    /**
     * Sets ID
     */
    public void setID(String id) {
        _id = id;
    }

    /**
     * Sets state.
     */
    public void setState(Object state) {
    }

    /**
     * Returns current state.
     */
    public Object getState() {
        return null;
    }
}

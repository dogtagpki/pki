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
 * Implements a status item component that displays a
 * line of text.  Used for menu descriptions, among other things.
 *
 * @see IStatusItem
 */
public class StatusItemText extends JLabel implements IStatusItem {
    protected String _id = null;

    /**
     * Returns empty status component
     */
    public StatusItemText(String id) {
        setID(id);
    }

    /**
     * Returns status component initialized with specified text.
     */
    public StatusItemText(String id, String s) {
        setID(id);
        setText(s);
    }

    /**
     * Returns the associated view Component.
     */
    public Component getComponent() {
        return this;
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
        setText(state.toString());
    }

    /**
     * Returns current state.
     */
    public Object getState() {
        return getText();
    }
}

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

package com.netscape.management.client.ug;

import java.awt.*;
import javax.swing.*;


/**
 * UGTextArea is a specialized JTextArea which disables focus management.
 * This allows TAB keys to allow traversal.
 */
public class UGTextArea extends JTextArea {

    /**
     * Constructor sets up a JTextArea needed for editing multi-valued
     * users and groups attributes.
     */
    public UGTextArea() {
        super();
        setLineWrap(true);
        setWrapStyleWord(true);
        setBorder(UIManager.getBorder("TextField.border"));

        // Starting with JDK 1.4, TAB traversal is enabled using the new
        // Component.setFocusTraversalKeys() method and isManagingFocus()
        // is deprectated. Enclose the calls to setFocusTraversalKeys()
        // into try block just in case an older version of JVM (1.2 or 1.3)
        // is running the Console.
        try {
            setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS, null);
            setFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS, null);
        }
            catch (Throwable ignore) {
        }
    }

    /**
      * Returns false to allow TAB traversal.
      *
      * @return false to allow TAB traversal
      */
    public boolean isManagingFocus() {
        return false;
    }
}

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
package com.netscape.management.client.util;

import javax.swing.*;
import javax.swing.text.*;

/**
 * SingleByteTextArea is a control which only accepts single byte input.
 * If the user types in double byte character, it beeps.
 */
public class SingleByteTextArea extends JTextArea {
    /**
      * Constructs a new TextArea with the specified text displayed.
      * A default model is created and rows/columns are set to 0.
      */
    public SingleByteTextArea() {
        super();
    }

    /**
      * Constructs a new SingleByteTextArea with the specified text displayed.
      * A default model is created and rows/columns are set to 0.
      */
    public SingleByteTextArea(String text) {
        super(text);
    }

    /**
      * @return SingleByteDocument
      * @overrides JTextArea.createDefaultModel()
      */
    protected Document createDefaultModel() {
        return new SingleByteDocument(this);
    }
}


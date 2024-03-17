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

import java.awt.*;


/**
 * AbstractModalDialog defines a basic dialog which consists of two main areas:
 * the custom panel and button panel. The custom panel can be used to set
 * the subclass's main view area. The button panel contains three buttons
 * whose labels are customizable: ok, cancel, and help.
 *
 * @author  Peter Lee (phlee@netscape.com)
 */

public abstract class AbstractModalDialog extends AbstractDialog {

    /**
     * Constructor for the dialog.
     */
    public AbstractModalDialog(Frame frame) {
        this(frame, "", OK | CANCEL | HELP);
    }

    /**
      * Constructor for the dialog.
      */
    public AbstractModalDialog(Frame frame, String title) {
        this(frame, title, OK | CANCEL | HELP);
    }

    /**
      * Constructor for the dialog which takes a parameter for the buttons
      * to display.
      */
    public AbstractModalDialog(Frame frame, String title, int type) {
        super(frame, title, true, type);
    }
}

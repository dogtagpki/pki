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
  * A class that represents feedback state in the UI.
  * The visual indication of this state appears in Console.
  */
public class FeedbackIndicator extends Cursor {
    public static final int FEEDBACK_DEFAULT = Cursor.DEFAULT_CURSOR;
    public static final int FEEDBACK_SELECT = Cursor.HAND_CURSOR;
    public static final int FEEDBACK_WAIT = Cursor.WAIT_CURSOR;


    /**
     * Creates a FeedbackIndicator object of FEEDBACK_DEFAULT type
     */
    public FeedbackIndicator() {
        super(FEEDBACK_DEFAULT);
    }

    /**
      * Creates a FeedbackIndicator object of specified type
      * @param type		specifies the state; must be one of FEEDBACK_* constants
      */
    public FeedbackIndicator(int type) {
        super(type);
    }
}

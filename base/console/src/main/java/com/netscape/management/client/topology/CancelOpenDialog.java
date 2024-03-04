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
package com.netscape.management.client.topology;

import java.awt.*;
import javax.swing.*;
import com.netscape.management.client.util.*;


/**
 * Dialog used to let user cancel opening the server console.
 *<p>
 * This used to be modal but has been changed to be nonmodal in case
 * additional dialogs must be displayed to gather additional information.
 * It is not desirable to have multiple modal dialogs open since the last
 * one displayed requires the first input.
 *
 * @author  Peter Lee (phlee@netscape.com)
 */

public class CancelOpenDialog extends AbstractDialog {

    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");

    private Thread _thread;


    /**
     * Constructor for the dialog
      *
      * @param title  the dialog title
      * @param label  the message to display
     */
    public CancelOpenDialog(String title, String label) {
        // This is a modal dialog to support synchronous processing, i.e.,
        // usage involves displaying the dialog, user interacting with the
        // dialog, and the code retrieving the data from the dialog before
        // continuing.
        super(new JFrame(), title, CANCEL);
        // Need to use an invisible parent because on some platforms such as NT,
        // when the dialog is dismissed, it has a tendency to bring the parent
        // frame to the front. This is undesirable because this would overlap
        // the window that was just opened.

        _thread = null;
        JLabel prompt = new JLabel(label);
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(panel, prompt, 0, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        setPanel(panel);
        setMinimumSize(250, 100);
        setResizable(false);
    }


    /**
       * Sets which thread is doing the work while this dialog is up. If the
      * dialog is canceled, then the thread is stopped.
      *
      * @param thread  the work thread
      * @see #cancelInvoked
      */
    public void setWorkThread(Thread thread) {
        _thread = thread;
    }


    /**
      * Overloads the super class's method to set the cursor accordingly. While
      * the dialog is visible, the cursor is busy.
      *
      * @param value  true or false
      */
    public void setVisible(boolean value) {
        if (value) {
            setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        } else {
            setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
        // This is needed for the reason stated above to display the dialog
        // relative to the visible parent JFrame. Without this, the dialog
        // will try to display relative to the invisible parent JFrame
        // used in the constructor.
        setParentFrame(UtilConsoleGlobals.getActivatedFrame());
        super.setVisible(value);
    }


    /**
      * Overloads the super class's method to handle the cancel event. Since the
      * user has selected cancel, stop the work thread if possible.
      */
    protected void cancelInvoked() {
        if (_thread != null) {
            _thread.stop();
        }
        super.cancelInvoked();
    }
}

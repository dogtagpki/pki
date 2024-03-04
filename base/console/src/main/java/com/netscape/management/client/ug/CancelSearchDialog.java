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
import com.netscape.management.client.util.*;


/**
 * Dialog used to let user cancel the search.
 *
 * @author  Peter Lee (phlee@netscape.com)
 */

public class CancelSearchDialog extends AbstractModalDialog {

    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");

    private Thread _thread;


    /**
     * Constructor for the dialog
     *
     * @param title  the dialog title
     * @param label  the message to display
     */
    public CancelSearchDialog(String title, String label) {
        this(null, title, label);
    }

    public CancelSearchDialog(Frame frame, String title, String label) {
        // This is a modal dialog to support synchronous processing, i.e.,
        // usage involves displaying the dialog, user interacting with the
        // dialog, and the code retrieving the data from the dialog before
        // continuing.
        super(frame, title, CANCEL);

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
        setBusyCursor(true);
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

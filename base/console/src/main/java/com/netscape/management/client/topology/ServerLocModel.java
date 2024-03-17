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

import javax.swing.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.UtilConsoleGlobals;

/**
	* An interface defining methods that can drive a hierarchical control, such
	* as a tree viewer.  Based on JFC's TreeModel Class, see
	* http://java.sun.com/products/jfc/swingdoc-0.3/doc/tree.html
	*
	* @author  terencek, ahakim
	* @version %I%, %G%
	* @see     com.netscape.management.client.IResourceModel
	*/
public class ServerLocModel extends ResourceModel {
    /**
      * constructor
      */
    public ServerLocModel() {
        super();
    }

    /**
      * set the status string when the model is busy
      *
      * @param text staus text
      */
    private void busyOn(String text) {
        JFrame f = UtilConsoleGlobals.getActivatedFrame();
        if (f != null && f instanceof Framework) {
            ((Framework)f).setBusyCursor(true);
            try {
                Thread.currentThread();
                Thread.sleep(200);
            } catch (Exception e) {}
        }
    }

    /**
      * turn off busy cursor
      */
    private void busyOff() {
        JFrame f = UtilConsoleGlobals.getActivatedFrame();
        if (f != null && f instanceof Framework) {
            ((Framework)f).setBusyCursor(false);
        }
    }
}

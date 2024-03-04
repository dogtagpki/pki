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
package com.netscape.management.client.console;

import java.awt.Frame;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.util.Vector;
import javax.swing.JPanel;
import javax.swing.JLabel;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.MultilineLabel;


/**
 * A dialog to query whether to restart the Directory Server.
 */
public class RestartDialog extends LoginDialog {
    protected static String RESOURCE_PREFIX = "restart";

    /**
     * constructor
     *
     * @param parentFrame	parent frame
     */
    public RestartDialog(Frame parentFrame) {
        this(parentFrame, "", "",
                Console._resource.getString(RESOURCE_PREFIX, "title"));
    }

    /**
      * constructor will take a userid and directory url
      *
      * @param parentFrame parent frame
      * @param userid user ID
      * @param url URL of the admin server
      */
    public RestartDialog(Frame parentFrame, String userid, String url) {
        this(parentFrame, userid, url,
                Console._resource.getString(RESOURCE_PREFIX, "title"));
    }

    /**
      * constructor will take a userid, directory url and a title
      *
      * @param parentFrame parent frame
      * @param userid user ID
      * @param url URL of the admin server
      * @param title dialog title
      */
    public RestartDialog(Frame parentFrame, String userid, String url,
            String title) {
        super(parentFrame, userid, url, new Vector(), title, RESOURCE_PREFIX);
    }

    /**
      * layout the UI
      *
      * @param panel dialog panel
      */
    protected void commonPanelLayout(JPanel panel) {
        // Add instructions to layout

        String s;
        JLabel l;

        int index = 0;
        while ((s = Console._resource.getString(RESOURCE_PREFIX,
                "instruction" + index++)) != null) {
            MultilineLabel ml = new MultilineLabel(s,1,50);
            GridBagUtil.constrain(panel, ml, 0,
                    GridBagConstraints.RELATIVE, 2, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.NONE, 0, 0, 0, 0);
        }

        s = Console._resource.getString(RESOURCE_PREFIX, "warning");
        l = new JLabel(s);
        l.setForeground(Color.red);
        GridBagUtil.constrain(panel, l, 0, GridBagConstraints.RELATIVE,
                2, 1, 0.0, 0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.NONE, DIFFERENT_COMPONENT_SPACE, 0,
                0, 0);

        super.commonPanelLayout(panel);
    }
}

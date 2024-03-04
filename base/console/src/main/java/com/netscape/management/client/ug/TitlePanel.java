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

import java.util.*;
import java.awt.*;
import javax.swing.*;
import com.netscape.management.nmclf.*;


/**
 * TitlePanel is used when creating a new object, such as user, group,
 * or organizational unit. This panel occupies the top portion of the
 * ResourceEditor.
 *
 * @see ResourceEditor
 * @see com.netscape.management.client.topology.ug.EditUserGroupPane
 */
public class TitlePanel extends JPanel implements Observer {
    JLabel _icon;
    JLabel _title;

    /**
    * Constructor
    */
    public TitlePanel() {
        _title = new SuiTitle("");
        _icon = new JLabel();

        GridBagLayout layout = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        setLayout(layout);
        c.fill = GridBagConstraints.BOTH;
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.insets = new Insets(SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.COMPONENT_SPACE);
        c.anchor = GridBagConstraints.WEST;
        c.weightx = 0;
        c.weighty = 0;
        layout.setConstraints(_icon, c);
        add(_icon);

        c.gridx = 1;
        c.weightx = 1;
        layout.setConstraints(_title, c);
        add(_title);

    }

    /**
     * Sets the title text.
     *
     * @param text  the title text
     */
    public void setText(String text) {
        _title.setText(text);
    }

    /**
     * Sets the title icon.
     *
     * @param icon  the title icon
     */
    public void setIcon(Icon icon) {
        _icon.setIcon(icon);
    }

    /**
     * Implements the Observer interface.
     *
     * @param observable  the observable object
     * @param o           value to update
     */
    public void update(Observable observable, Object o) {
    }
}

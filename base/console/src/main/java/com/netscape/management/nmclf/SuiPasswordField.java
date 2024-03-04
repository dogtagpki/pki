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
package com.netscape.management.nmclf;

import javax.swing.*;

/**
 * An extended JPasswordField to fix a JFC bug where
 * it does not disable correctly.
 *
 * Also allows border to be made invisible, which
 * is required to display text in read-only.
 *
 * @author ahakim@netscape.com
 * @see #setTransparentBorder(boolean)
 */
public class SuiPasswordField extends JPasswordField {
    boolean _changeBorder = false;

    public SuiPasswordField() {
        super();
    }

    public SuiPasswordField(String title) {
        super(title);
    }

    public SuiPasswordField(int cols) {
        super(cols);
    }

    public void setTransparentBorder(boolean changeBorder) {
        _changeBorder = changeBorder;
    }

    public void setEnabled(boolean state) {
        super.setEnabled(state);
        if (state) {
            setBackground(UIManager.getColor("window"));
            if (_changeBorder)
                setBorder(UIManager.getBorder("PasswordField.border"));
        } else {
            setBackground(UIManager.getColor("control"));
            if (_changeBorder)
                setBorder(BorderFactory.createEmptyBorder());
        }
    }
}

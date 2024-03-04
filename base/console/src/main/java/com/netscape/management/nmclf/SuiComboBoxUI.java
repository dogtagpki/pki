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
import javax.swing.plaf.*;
import javax.swing.plaf.basic.*;

/**
 * A custom UI for JComboBox. The only purpose of this customization
 * is to set the SuiListCellRenderer as the renderer to have a proper
 * right edge cell spacing as for the lists.
 *
 * Note: The ComboBox.renderer can not be set with UIDefaults properties,
 * so we need to implement a custom ComboBoxUI.
 */
public class SuiComboBoxUI extends BasicComboBoxUI implements SuiConstants {
    public SuiComboBoxUI() {
        super();
    }

    public static ComponentUI createUI(JComponent c) {
        return new SuiComboBoxUI();
    }

    public void installUI(JComponent c) {
        ((JComboBox)c).setRenderer(new SuiListCellRenderer());
        super.installUI(c);
    }
}

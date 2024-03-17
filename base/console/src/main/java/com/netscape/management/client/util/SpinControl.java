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

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import com.netscape.management.nmclf.*;

/**
 * A control that has two buttons, up or down.  It is usually
 * placed adjacent to a numeric text field to facilitate
 * incrementing and decrementing its value.
 *
 * @todo make public
 */
class SpinControl extends JPanel implements SuiConstants, ActionListener {
    JComponent parent;
    Vector spinListeners = new Vector();
    JButton upButton, downButton;

    public SpinControl(JComponent parent) {
        GridBagLayout gridbag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        setLayout(gridbag);
        setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 0));

        upButton = new SpinUpButton();
        upButton.addActionListener(this);
        downButton = new SpinDownButton();
        downButton.addActionListener(this);
        downButton.setMargin(new Insets(1, 4, 1, 4));

        GridBagUtil.constrain(this, upButton, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(this, downButton, 0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
    }

    public void setToolTipText(String toolTip) {
        upButton.setToolTipText(toolTip);
        downButton.setToolTipText(toolTip);
    }

    public void addSpinListener(ISpinListener l) {
        this.spinListeners.addElement(l);
    }

    public void removeSpinListener(ISpinListener l) {
        this.spinListeners.removeElement(l);
    }

    public void actionPerformed(ActionEvent event) {
        boolean isUp = event.getSource() instanceof SpinUpButton;
        for (Enumeration e = spinListeners.elements();
                e.hasMoreElements();) {
            ISpinListener l = (ISpinListener) e.nextElement();
            if (isUp)
                l.actionUp(new SpinEvent(this));
            else
                l.actionDown(new SpinEvent(this));
        }
        //parent.requestFocus();
    }

    class SpinButton extends JButton {
        public SpinButton(int direction) {
            super(new ArrowIcon(direction));
            setMargin(new Insets(1, 4, 1, 4));
        }

        public boolean isFocusTraversable() {
            return false;
        }
    }

    class SpinUpButton extends SpinButton {
        public SpinUpButton() {
            super(SwingConstants.NORTH);
        }
    }

    class SpinDownButton extends SpinButton {
        public SpinDownButton() {
            super(SwingConstants.SOUTH);
        }
    }
}

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

import java.awt.*;
import javax.swing.*;
import javax.swing.plaf.*;
import javax.swing.plaf.basic.*;
import com.netscape.management.client.util.*;


/**
 * A UI for JOptionPane to address these visual issues:
 * - custom icons used
 * - button text internationalized
 * - button sizes set to UE specs
 * - inter-button spacing set to UE specs
 */
public class SuiOptionPaneUI extends BasicOptionPaneUI implements SuiConstants {
    public SuiOptionPaneUI() {
        super();
    }

    public static ComponentUI createUI(JComponent c) {
        return new SuiOptionPaneUI();
    }

    public void installUI(JComponent c) {
        super.installUI(c);
    }

    /**
      * Returns the insets to be used in the Container housing the buttons.
      */
    protected Insets getButtonInsets() {
        return new Insets(COMPONENT_SPACE, HORIZ_DIALOG_INSET,
                VERT_DIALOG_INSET, HORIZ_DIALOG_INSET);
    }

    /**
      * Returns the buttons to display from the JOptionPane the receiver is
      * providing the look and feel for. If the JOptionPane has options
      * set, they will be provided, otherwise if the optionType is
      * YES_NO_OPTION, yesNoOptions is returned, if the type is
      * YES_NO_CANCEL_OPTION yesNoCancelOptions is returned, otherwise
      * defaultButtons are returned.
      */
    public Object[] getButtons() {
        if (optionPane != null) {
            Object[] suppliedOptions = optionPane.getOptions();

            if (suppliedOptions == null) {
                int type = optionPane.getOptionType();

                if (type == JOptionPane.YES_NO_OPTION)
                    return new JButton[] { JButtonFactory.createYesButton(
                            new ButtonActionListener(0)),
                    JButtonFactory.createNoButton(
                            new ButtonActionListener(1))};
                else if (type == JOptionPane.YES_NO_CANCEL_OPTION)
                    return new JButton[] { JButtonFactory.createYesButton(
                            new ButtonActionListener(0)),
                    JButtonFactory.createNoButton(
                            new ButtonActionListener(1)),
                    JButtonFactory.createCancelButton(
                            new ButtonActionListener(2))};
                else if (type == JOptionPane.OK_CANCEL_OPTION)
                    return new JButton[] { JButtonFactory.createOKButton(
                            new ButtonActionListener(0)),
                    JButtonFactory.createCancelButton(
                            new ButtonActionListener(1))};
                else
                    return new JButton[] { JButtonFactory.createOKButton(
                            new ButtonActionListener(0)), };
            }
            return suppliedOptions;
        }
        return null;
    }

    protected Container createButtons() {
        Box box = new Box(SwingConstants.HORIZONTAL);
        box.add(Box.createHorizontalGlue());

        Object object[] = getButtons();
        JButton button[] = new JButton[object.length];
        for (int i = 0; i < object.length; i++) {
            if (object[i] instanceof String) {
                button[i] = new JButton((String) object[i]);
                button[i].addActionListener(new ButtonActionListener(i));
            } else if (object[i] instanceof JButton) {
                button[i] = (JButton) object[i];
            }

            box.add(Box.createHorizontalStrut(COMPONENT_SPACE));
            box.add(button[i]);
        }
        JButtonFactory.resize(button);
        return box;
    }
    
    /*
    class ButtonActionListener implements ActionListener {
        int _buttonIndex = 0;

        public ButtonActionListener(int i) {
            _buttonIndex = i;
        }

        public void actionPerformed(ActionEvent e) {
            createdButtonFired(_buttonIndex);
        }
       }
     */

    /**
      * Returns the icon to use for the passed in type.
      */
    public Icon getIconForType(int messageType) {
        if (messageType < 0 || messageType > 3)
            return null;
        switch (messageType) {
        case 0:
            return UIManager.getIcon("OptionPane.errorIcon");
        case 1:
            return UIManager.getIcon("OptionPane.informationIcon");
        case 2:
            return UIManager.getIcon("OptionPane.warningIcon");
        case 3:
            return UIManager.getIcon("OptionPane.questionIcon");
        }
        return null;
    }
}

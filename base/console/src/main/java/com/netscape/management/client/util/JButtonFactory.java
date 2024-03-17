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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import com.netscape.management.nmclf.SuiLookAndFeel;


/**
 * Provides a set of utility methods to create and manipulate
 * JButton objects according to predefined UI guidelines.
 *
 * The objective is to create buttons that appear visually consistant.
 */
public class JButtonFactory extends Object {
    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");
    private static final JPanel _panel = new JPanel(); // Used to force button layout to get the initial preferred size.
    private static final int _defaultWidth =
            SuiLookAndFeel.BUTTON_SIZE_MULTIPLE; // Default button width


            /**
     * Returns the height for the JButton.
     *
     * @param button  the JButton to get the height for
     * @return        the button's height
     */
    public static int getHeight(JButton button) {
        if (button == null) {
            return 0;
        }

        _panel.removeAll(); // Remove previous button

        JButton tmp = new JButton(button.getText()); // In case button already has a size
        _panel.add(tmp);
        _panel.doLayout(); // Force the layout of the button.

        int height = tmp.getHeight();

        Debug.println(9, "JButtonFactory: button height = " + height);

        return height;
    }


    /**
      * Returns the width for the JButton.
      *
      * @param button  the JButton to get the width for
      * @return        the button's width
      */
    public static int getWidth(JButton button) {
        if (button == null) {
            return 0;
        }

        _panel.removeAll(); // Remove previous button

        JButton tmp = new JButton(button.getText()); // In case button already has a size
        _panel.add(tmp);
        _panel.doLayout(); // Force the layout of the button.

        int width = tmp.getWidth();
        width = width + _defaultWidth - (width % _defaultWidth);

        Debug.println(9, "JButtonFactory: button width = " + width);

        return width;
    }


    /**
      * Creates a new JButton with the specified label. Uses the label to size
      * the button to the appropriate multiple.
      *
      * @param label  the String text for the JButton to create
      */
    public static JButton create(String label) {
        JButton button = new JButton(label);
        JButtonFactory.resize(button);
        return button;
    }

    /**
      * Creates a new JButton with the specified label. Uses the label to size
      * the button to the appropriate multiple.
      *
      * @param label   the String text for the JButton to create
      * @param l       listener for this button
      * @param command the command string for this action event
      */
    public static JButton create(String label, ActionListener l,
            String command) {
        JButton button = create(label);
        button.addActionListener(l);
        button.setActionCommand(command);
        initializeMnemonic(button);
        return button;
    }


    /**
      * Creates a new cancel button and sets up action listener for it.
      *
      * @param l  listener for this button
      */
    public static JButton createDeleteButton(ActionListener l) {
        JButton button = create(_resource.getString(null, "DeleteButtonLabel"));
        button.addActionListener(l);
        button.setActionCommand("DELETE");
        initializeMnemonic(button);
        JButtonFactory.resize(button);
        return button;
    }


    /**
      * Creates a new cancel button and sets up action listener for it.
      *
      * @param l  listener for this button
      */
    public static JButton createCancelButton(ActionListener l) {
        JButton button = create(_resource.getString(null, "CancelButtonLabel"));
        button.addActionListener(l);
        button.setActionCommand("CANCEL");
        button.registerKeyboardAction(l, "CANCEL",
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        JButtonFactory.resize(button);
        return button;
    }


    /**
      * Creates a new Help button and sets up action listener for it.
      *
      * @param l  listener for this button
      */
    public static JButton createHelpButton(ActionListener l) {
        JButton button = create(_resource.getString(null, "HelpButtonLabel"));
        button.addActionListener(l);
        button.setActionCommand("HELP");
        initializeMnemonic(button);
        JButtonFactory.resize(button);
        return button;
    }


    /**
      * Creates a new No button and sets up action listener for it.
      *
      * @param l  listener for this button
      */
    public static JButton createNoButton(ActionListener l) {
        JButton button = create(_resource.getString(null, "NoButtonLabel"));
        button.addActionListener(l);
        button.setActionCommand("NO");
        JButtonFactory.resize(button);
        return button;
    }


    /**
      * Creates a new Yes button and sets up action listener for it.
      *
      * @param l  listener for this button
      */
    public static JButton createYesButton(ActionListener l) {
        JButton button = create(_resource.getString(null, "YesButtonLabel"));
        button.addActionListener(l);
        button.setActionCommand("YES");
        JButtonFactory.resize(button);
        return button;
    }


    /**
      * Creates a new OK button and sets up action listener for it.
      *
      * @param l  listener for this button
      */
    public static JButton createOKButton(ActionListener l) {
        JButton button = create(_resource.getString(null, "OKButtonLabel"));
        button.addActionListener(l);
        button.setActionCommand("OK");
        JButtonFactory.resize(button);
        return button;
    }


    /**
      * Creates a new close button and sets up action listener for it.
      *
      * @param l  listener for this button
      */
    public static JButton createCloseButton(ActionListener l) {
        JButton button = create(_resource.getString(null, "CloseButtonLabel"));
        button.addActionListener(l);
        button.setActionCommand("CLOSE");
        button.registerKeyboardAction(l, "CLOSE",
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        initializeMnemonic(button);
        JButtonFactory.resize(button);
        return button;
    }


    /**
      * Creates an array of JButtons with the specified labels. This method
      * sizes all of the buttons to the longest label.
      *
      * @param labels  an array of String texts for the JButtons to create
      */
    public static JButton[] create(String[] labels) {
        if (labels.length == 0) {
            return null;
        }
        JButton[] buttons = new JButton[labels.length];
        for (int i = 0; i < buttons.length; i++) {
            buttons[i] = new JButton(labels[i]);
        }
        JButtonFactory.resize(buttons);
        return buttons;
    }


    /**
      * Resizes the JButton to the correct multiple based on the button's label.
      *
      * @param button  the JButton to resize
      */
    public static void resize(JButton button) {
        if (button == null) {
            return;
        }
        int width = JButtonFactory.getWidth(button);
        int height = JButtonFactory.getHeight(button);
        Dimension dim = new Dimension(width, height);
        button.setPreferredSize(dim);
        button.setMinimumSize(dim);
    }


    /**
      * Resizes the JButtons to the correct multiple of the longest label.
      *
      * @param buttons  an array of JButtons to resize
      */
    public static void resize(JButton[] buttons) {
        if (buttons.length == 0) {
            return;
        }
        int width = JButtonFactory.getWidth(buttons[0]);
        int height = JButtonFactory.getHeight(buttons[0]);
        int maxWidth = width;
		if (buttons.length == 1)
		{
			JButton cancelButton = create(_resource.getString(null,"CancelButtonLabel"));
			width = JButtonFactory.getWidth(cancelButton);
            height = JButtonFactory.getHeight(cancelButton);
            maxWidth = width;
		}
		
        for (int i = 1; i < buttons.length; i++) {
            width = JButtonFactory.getWidth(buttons[i]);
            maxWidth = Math.max(maxWidth, width);
        }
        Dimension dim = new Dimension(maxWidth, height);
        for (int i = 0; i < buttons.length; i++) {
            if (buttons[i] != null) {
                buttons[i].setPreferredSize(dim);
                buttons[i].setMinimumSize(dim); // Force smaller buttons up to the size of the largest ones.
            }
        }
    }


    /**
      * Convenience routine to resize a group of two JButtons.
      *
      * @param button1  first JButton to resize
      * @param button2  next JButton to resize
      */
    public static void resizeGroup(JButton button1, JButton button2) {
        JButton buttons[] = new JButton[]{ button1, button2, };
        resize(buttons);
    }


    /**
      * Convenience routine to resize a group of three JButtons.
      *
      * @param button1  first JButton to resize
      * @param button2  next JButton to resize
      * @param button3  next JButton to resize
      */
    public static void resizeGroup(JButton button1, JButton button2,
            JButton button3) {
        JButton buttons[] = new JButton[]{ button1, button2, button3, };
        resize(buttons);
    }


    /**
      * Convenience routine to resize a group of four JButtons.
      *
      * @param button1  first JButton to resize
      * @param button2  next JButton to resize
      * @param button3  next JButton to resize
      * @param button4  next JButton to resize
      */
    public static void resizeGroup(JButton button1, JButton button2,
            JButton button3, JButton button4) {
        JButton buttons[] = new JButton[]{ button1, button2, button3,
        button4, };
        resize(buttons);
    }


    /**
      * Resizes the JButton to be the same size as the reference JButton.
      *
      * @param reference  the JButton to size to
      * @param target     the JButton to resize
      */
    public static void resize(JButton reference, JButton target) {
        if (reference == null || target == null) {
            return;
        }
        Dimension dim = reference.getPreferredSize();
        target.setPreferredSize(dim);
        target.setMinimumSize(dim);
    }


    /**
      * Resizes the JButtons to the correct multiple of the longest label.
      *
      * @param reference  the JButton to size to
      * @param targets    an array of JButtons to resize
      */
    public static void resize(JButton reference, JButton[] targets) {
        if (reference == null) {
            return;
        }
        if (targets.length == 0) {
            return;
        }
        Dimension dim = reference.getPreferredSize();
        for (int i = 0; i < targets.length; i++) {
            if (targets[i] != null) {
                targets[i].setPreferredSize(dim);
                targets[i].setMinimumSize(dim);
            }
        }
    }

    /**
      * Creates a new JButton with an arrow facing LEFT and specified text.
      *
      * @param label   the String text for the JButton to create
      * @param l       listener for this button
      * @param command the command string for this action event
      */
    public static JButton createLeftArrowButton(String label,
            ActionListener l, String command) {
        JButton button = create(label);
        initArrowButton(button, JButton.RIGHT, l, command);
        return button;
    }

    /**
      * Creates a new JButton with an arrow facing RIGHT and specified text.
      *
      * @param label   the String text for the JButton to create
      * @param l       listener for this button
      * @param command the command string for this action event
      */
    public static JButton createRightArrowButton(String label,
            ActionListener l, String command) {
        JButton button = create(label);
        initArrowButton(button, JButton.LEFT, l, command);
        return button;
    }

    /**
      * Initializes a JButton as an arrow button.
      * Sets the arrow icon and the mnemonic character.
      *
      * @param button  the button to be converted to an arrow button
      * @param textPosition horizontal text position in respect to the icon
      * @param l       listener for this button
      * @param command the command string for this action event
      */
    public static void initArrowButton(JButton button, int textPosition,
            ActionListener l, String command) {
        button.setHorizontalTextPosition(textPosition);
        if (textPosition == JButton.LEFT) {
            button.setIcon(new ArrowIcon(ArrowIcon.EAST, 5));
        }
        else {
            button.setIcon(new ArrowIcon(ArrowIcon.WEST, 5));
        }
        button.addActionListener(l);
        button.setActionCommand(command);
        initializeMnemonic(button);
    }

    /**
     * Sets mnemonic for the specified button.
     * The button is expected to have text where ampersand '&'
     * is put in front of the mnemonic character. The ampersand
     * will be removed from the text.
     * 
     * @param button the button to set the mnemonic on
     */
    public static void initializeMnemonic(JButton button){
        String label = button.getText();
        char mnemonicChar = UITools.getMnemonic(label); 
        if (mnemonicChar != 0) {
            button.setText(UITools.getDisplayLabel(label));
            button.setMnemonic(mnemonicChar);
        }
    }
}

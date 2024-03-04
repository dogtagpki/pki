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
package com.netscape.management.client.components;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import com.netscape.management.client.util.*;


/**
 * Provides a set of utility methods to create 
 * buttons according to standard UI guidelines.
 * 
 * Use the createButton(...) or createPredefinedButton()
 * methods instead of new JButton(...) to generate buttons.
 * 
 * Optionally use resizeButtons(...) methods to set sizes for 
 * groups of buttons.
 */
public class ButtonFactory
{
    private static ResourceSet resource = new ResourceSet("com.netscape.management.client.components.components");
    private static final JPanel scratchPanel = new JPanel(); // Used to force button layout to get the initial preferred size.
	private static final String IMAGE_PATH = "com/netscape/management/client/components/images/";
	private static final int BUTTON_SIZE_MULTIPLE = UIConstants.BUTTON_SIZE_MULTIPLE;
	
	/**
	 * Button Arrow Icons.  Use these icons to create 
	 * a button with an image.  For example:
	 * <CODE>
	 *  JButton addButton = ButtonFactory.createButton(i18n("&Move"), new AddListener(), "MOVE_COMMAND");
     *   addButton.setHorizontalTextPosition(JButton.LEFT);
     *   addButton.setIcon(ButtonFactory.DOWN_ICON);
     *   JButtonFactory.resizeButton(addButton);
	 * </CODE>
	 */
	public static ImageIcon UP_ICON = new RemoteImage(IMAGE_PATH + "upArrow.gif");
	public static ImageIcon DOWN_ICON = new RemoteImage(IMAGE_PATH + "downArrow.gif");
	public static ImageIcon LEFT_ICON = new RemoteImage(IMAGE_PATH + "leftArrow.gif");
	public static ImageIcon RIGHT_ICON = new RemoteImage(IMAGE_PATH + "rightArrow.gif");
	
	/**
	 * Predefined Button Types for use with createPredefinedButton()
	 */
	public final static String OK = "OK";
	public final static String CANCEL = "CANCEL";
	public final static String CLOSE = "CLOSE";
	public final static String YES = "YES";
	public final static String NO = "NO";
	public final static String BROWSE = "BROWSE";
	public final static String ADD = "ADD";
	public final static String NEW = "NEW";
	public final static String EDIT = "EDIT";
	public final static String REMOVE = "REMOVE";
	public final static String HELP = "HELP";

	/**
	 * Returns a localized string from the predefined 
	 * resource bundle and group for this class.
	 * 
	 * @return localized string
	 */
    private static String i18n(String id) 
    {
        return resource.getString("buttons", id);
    }

    /**
      * Sets label for specified button.
      * If label contains a mnenomic (specified by ampersand & in label)
      * the appropriate accelerator key is set.
      * See the Java Look and Feel Guidelines on how to
      * choose mnemonic characters.
      * 
      * @param button  the button for which to set label
      * @param label   localized text displayed on this button
      * 
      * @see http://java.sun.com/products/jlf/dg/higi.htm#35796
      */
    public static void setButtonText(JButton button, String label)
    {
        button.setText(ComponentFactory.stripAmpersand(label));
        char mnemonicChar = ComponentFactory.getMnemonic(label); 
		if (mnemonicChar != 0) 
		{
            button.setMnemonic(mnemonicChar);
        }
    }
    
	
    /**
      * Creates a new JButton with the specified label.
      * If label contains a mnenomic (specified by ampersand & in label)
      * the appropriate accelerator key is set.
      * See the Java Look and Feel Guidelines on how to
      * choose mnemonic characters.
      * The button is horizontally sized to a 15 pixel multiple.
      *
      * @param label   localized text displayed on this button -or- a button type
      *                if label contains a mnemonic (specified &) the ampersand is stripped out.
      * @return        new JButton object
      * @see http://java.sun.com/products/jlf/dg/higi.htm#35796
      */
	public static JButton createButton(String label)
	{
		JButton button = new JButton();
        setButtonText(button, label);
        resizeButton(button);
        return button;
    }

    /**
      * Creates a new JButton with the specified label.
      * If label contains a mnenomic (specified by ampersand & in label)
      * the appropriate accelerator key is set.
      * See the Java Look and Feel Guidelines on how to
      * choose mnemonic characters.
      * The button is horizontally sized to a 15 pixel multiple.
      * The specified actionlistener is set on the button.
      *
      * @param label   the text displayed on this button.  
      *                if label contains a mnemonic (specified &) the ampersand is stripped out.
      * @param l       the listener that receives notification on button press
      * @param command the string identifying the command for button press event
      * @return        new JButton object
      */
    public static JButton createButton(String label, ActionListener l, String command) 
	{
        JButton button = createButton(label);
        button.addActionListener(l);
        button.setActionCommand(command);
        return button;
    }
	
	/**
	 * Creates a new JButton of a predefined type.
	 * The button type may be one of the following constants:
     * OK, CANCEL, YES, NO, BROWSE, or HELP.
     * An appropriate localized label will be used for its name.
     * An appropriate keyboard shortcut will be registered
     * on the button (e.g. Enter for OK)
     * The button is horizontally sized to a 15 pixel multiple.
     * The specified actionlistener is set on the button.
     * The command for the action event is the same as button type constant.
     * 
     * @param buttonType    the type of predefined button to create
     * @param l             the listener that receives notification on button press
     * @return              new JButton object
	 */
	public static JButton createPredefinedButton(String buttonType, ActionListener l)
	{
		String label = i18n(buttonType);
		if(label == null)
			throw new IllegalArgumentException("Invalid button type: " + buttonType);
		
		JButton button = createButton(label, l, buttonType);
		if(buttonType.equals(OK) || buttonType.equals(YES))
		{
			button.registerKeyboardAction(l, buttonType, 
										  KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), 
										  JComponent.WHEN_IN_FOCUSED_WINDOW);
		}
		else
		if(buttonType.equals(CANCEL) || buttonType.equals(NO))
		{
			button.registerKeyboardAction(l, buttonType, 
										  KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), 
										  JComponent.WHEN_IN_FOCUSED_WINDOW);
		}
		else
		if(buttonType.equals(HELP))
		{
			button.registerKeyboardAction(l, buttonType,
			        KeyStroke.getKeyStroke(KeyEvent.VK_F1,0),
			        JComponent.WHEN_IN_FOCUSED_WINDOW);
		}
		return button;
	}
	
    /**
      * Resizes the JButton to the correct multiple based on 
      * the button's label and icon.
      *
      * @param button  the JButton to resize
      */
	public static void resizeButton(JButton button) 
	{
        JButton tmp = new JButton(button.getText(), button.getIcon());
        scratchPanel.removeAll(); // Remove previous button
        scratchPanel.add(tmp);
        scratchPanel.doLayout();
		scratchPanel.remove(tmp);
		int width = tmp.getWidth();
        width += BUTTON_SIZE_MULTIPLE - (width % BUTTON_SIZE_MULTIPLE);
        Dimension dim = new Dimension(width, tmp.getHeight());
        button.setMinimumSize(dim);
        button.setPreferredSize(dim);
    }


    /**
      * Resizes the JButtons to the correct multiple of the longest label.
      *
      * @param buttons  an array of JButtons to resize
      */
	public static void resizeButtons(JButton[] buttons) 
	{
        if (buttons.length == 0) {
            return;
        }
        int width = getWidth(buttons[0]);
        int height = getHeight(buttons[0]);
        int maxWidth = width;
        int maxHeight = height;
		for (int i = 1; i < buttons.length; i++) 
		{
            width = getWidth(buttons[i]);
			height = getHeight(buttons[i]);
            maxWidth = Math.max(maxWidth, width);
            maxHeight = Math.max(maxHeight, height);
        }
        Dimension dim = new Dimension(maxWidth, maxHeight);
		for (int i = 0; i < buttons.length; i++) 
		{
			if (buttons[i] != null) 
			{
                buttons[i].setPreferredSize(dim);
                buttons[i].setMinimumSize(dim); // Force smaller buttons up to the size of the largest ones.
            }
        }
    }


    /**
      * Convenience routine to resize a group of two JButtons.
      *
      * @param button1  first JButton to resize
      * @param button2  second JButton to resize
      */
	public static void resizeButtons(JButton button1, JButton button2)
	{
        JButton buttons[] = new JButton[]{ button1, button2};
        resizeButtons(buttons);
    }


    /**
      * Convenience routine to resize a group of three JButtons.
      *
      * @param button1  first JButton to resize
      * @param button2  second JButton to resize
      * @param button3  third JButton to resize
      */
	public static void resizeButtons(JButton button1, JButton button2, JButton button3) 
	{
        JButton buttons[] = new JButton[]{ button1, button2, button3 };
        resizeButtons(buttons);
    }


    /**
      * Convenience routine to resize a group of four JButtons.
      *
      * @param button1  first JButton to resize
      * @param button2  second JButton to resize
      * @param button3  third JButton to resize
      * @param button4  fourth JButton to resize
      */
	public static void resizeButtons(JButton button1, JButton button2, JButton button3, JButton button4) 
	{
        JButton buttons[] = new JButton[]{ button1, button2, button3, button4 };
        resizeButtons(buttons);
    }

    /**
     * Returns the height for the JButton.
     *
     * @param button  the JButton to get the height for
     * @return        the button's height
     */
    private static int getHeight(JButton button) {
        JButton tmp = new JButton(button.getText(), button.getIcon());
        scratchPanel.removeAll(); // Remove previous button
        scratchPanel.add(tmp);
        scratchPanel.doLayout();
		scratchPanel.remove(tmp);
        return tmp.getHeight();
    }


    /**
      * Returns the width for the JButton.
      *
      * @param button  the JButton to get the width for
      * @return        the button's width
      */
    private static int getWidth(JButton button) {
        JButton tmp = new JButton(button.getText(), button.getIcon());
        scratchPanel.removeAll(); // Remove previous button
        scratchPanel.add(tmp);
        scratchPanel.doLayout();
		scratchPanel.remove(tmp);
        int width = tmp.getWidth();
        width = width + BUTTON_SIZE_MULTIPLE - (width % BUTTON_SIZE_MULTIPLE);
        return width;
    }
}

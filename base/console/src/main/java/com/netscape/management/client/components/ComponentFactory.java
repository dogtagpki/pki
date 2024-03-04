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

/**
 * ComponentFactory is a collection of static methods that
 * create various types of commonly used components that 
 * are initialized for particular behaviors, beyond what 
 * is possible by their constructors. 
 * 
 * For example, it is very common in UI to create a label
 * and field combination.  There is a certain amount of 
 * common work, such as spacing between the two components 
 * and keyboard accelerator support.  The factory method 
 * <code>createLabelComponent(String, JComponent)</code>
 * makes that task easier.
 * 
 * Later, additional factory methods will be added to support
 * radio buttons, etc.
 * 
 * @author Andy Hakim
 */
public class ComponentFactory
{
    /**
      * Creates JLabel/JComponent pair with keyboard shortcut support.
      * If the label string contains a mnenomic (specified by ampersand &)
      * an accelerator key binding is set on the parent component.
      * When that accelerator key is pressed, the child component gets focus.
      * 
      * The JLabel appears above the specified JComponent.  
      * Both are enclosed in a JPanel, which is returned.
      * 
      * @param label   localized text displayed in this label
      * @param c       component that is associated with this label
      * @return        a JPanel that contains both the JLabel and JComponent.
      */
    public static JPanel createLabelComponent(String labelText, JComponent c)
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(3, 0, 0, 0);
        JLabel label = new JLabel(stripAmpersand(labelText));
        label.setLabelFor(c);
        gbl.setConstraints(label, gbc);
        p.add(label);
            
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbl.setConstraints(c, gbc);
        p.add(c);
        
        if(c instanceof JScrollPane)
        {
            JScrollPane sp = (JScrollPane)c;
            Component comp = sp.getViewport().getView();
            if(comp instanceof JComponent)
                c = (JComponent)comp;
        }
        
        char mnemonicChar = getMnemonic(labelText);
        if(Character.isLetter(mnemonicChar))
        {
            label.setDisplayedMnemonic(mnemonicChar);
            makeKeyboardShortcut(label, c, mnemonicChar);
        }

        return p;            
    }
    
    /**
     * Associates a keyboard shortcut between the parent and child component.
     * An internal listener is created to handle the key press action.
     */
    public static void makeKeyboardShortcut(JComponent parent, JComponent child, char c)
    {
        KeyStroke k = KeyStroke.getKeyStroke(c);
        parent.registerKeyboardAction(new KeyActionListener(child), k, JComponent.WHEN_IN_FOCUSED_WINDOW);
    }

    /**
     * Removes the ampersand (&) character from a string.
     * Only the first occurance of & is removed.
     * For example:
     * stripAmpersand("&File") returns "File"
     * 
     * @return a new string without the ampersand.
     */
    public static String stripAmpersand(String label) 
    {
        if (label != null) 
        {
            int mnemonicIndex = label.indexOf('&');
            if (mnemonicIndex != -1) 
            {
                try 
                {
                    char mnemonicChar =
                            label.charAt(mnemonicIndex + 1); // given "a&bc", return 'b'
                            String tmpLabel = label.substring(0, mnemonicIndex); // return "a"
                            String dispLabel = tmpLabel.concat(label.substring(mnemonicIndex + 1)); // concat "bc"
                            return dispLabel;
                }
                catch (StringIndexOutOfBoundsException e) 
                {
                    System.err.println("Error parsing label: " + label);
                }
            }
        }
        return label;
    }

    /**
     * Return mnemonic character (char following &) from label
     * See the Java Look and Feel Guidelines on how to choose mnemonic characters.
     * For example:
     * getMnemonic("&File") returns 'F'
     * 
     * @see http://java.sun.com/products/jlf/dg/higi.htm#35796
     */
    public static char getMnemonic(String label) {
        if (label != null) 
        {
            int mnemonicIndex = label.indexOf('&');
            if (mnemonicIndex != -1) 
            {
                try 
                {
                    char mnemonicChar = label.charAt(mnemonicIndex + 1); // given "a&bc", return 'b'
                    return mnemonicChar;
                }
                catch (StringIndexOutOfBoundsException e) 
                {
                    System.err.println("Error parsing mnemonic: " + label);
                }
            }
        }
        return 0;
    }

}

class KeyActionListener implements ActionListener
{
    JComponent assocatedComponent;
        
    public KeyActionListener(JComponent c)
    {
        assocatedComponent = c;
    }
        
    public void actionPerformed(ActionEvent e)
    {
        assocatedComponent.grabFocus();
    }
}

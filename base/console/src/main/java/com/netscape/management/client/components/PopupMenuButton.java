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

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import com.netscape.management.client.util.*;

 /**
 * The PopupmenuButton is a push button that opens a popup menu when
 * invoked. The popup menu is aligned with the top edge of the button.
 * In the current implementation, Keyboard navigation is not fully
 * supported for nested menus.
 */
public class PopupMenuButton extends JButton  {
    
    private JPopupMenu _popup;

    /**
     * Constructor
     * @param text The button text
     * @param popup The popum menu to be opened when the button is invoked 
     */
    public PopupMenuButton(String text, JPopupMenu popup) {
        super(text);
        JButtonFactory.initArrowButton(this, JButton.LEFT, 
            new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    showPopup();
                }
            }, "");

        _popup = popup;
        installKeyboardActions();
    }

    /**
     * Returns the current popup menu
     * @return The popup menu
     */
    public JPopupMenu getPopupMenu() {
       return _popup;
    }

    /**
     * Show popup on the screen with the proper alignment relative 
     * to the button
     */
    private void showPopup() {
        Point l = getLocation();
        Dimension d = getSize();
        if (getParent() != null) {
            _popup.show(getParent(), l.x + d.width, l.y);
        }
    }

    /**
     * Install actions for handling keyboard navigation
     */
    protected void installKeyboardActions() {
        registerKeyboardAction(new HidePopupAction(),
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE,0,false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
        registerKeyboardAction(new SelectNextItemAction(),
            KeyStroke.getKeyStroke(KeyEvent.VK_DOWN,0,false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
        registerKeyboardAction(new SelectPreviousItemAction(),
            KeyStroke.getKeyStroke(KeyEvent.VK_UP,0,false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
        registerKeyboardAction(new ShowPopupAction(),
            KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT,0,false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
        registerKeyboardAction(new ReturnAction(),
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,0,false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
        registerKeyboardAction(new ReturnAction(),
            KeyStroke.getKeyStroke(KeyEvent.VK_SPACE,0,false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
     }

         
    /**
      *  Show Popup Action
      */
    private class ShowPopupAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
             if (!_popup.isVisible()) {
                 showPopup();
             }
        }
    }

    /**
      * Hide Popup Action
      */
    private class HidePopupAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
             _popup.setVisible(false);
                 
        }
    }

    /**
     * Handle return key in the popup menu. This code is borrowed
     * from swing.plaf.basic.BasicMenuUI
     */
    private class ReturnAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
             if (!_popup.isVisible()) {
                 showPopup();
             }
             else {
                MenuElement path[] = MenuSelectionManager.defaultManager().getSelectedPath();
                MenuElement lastElement;
                if(path.length > 0) {
                    lastElement = path[path.length-1];
                    if(lastElement instanceof JMenu) {
                        MenuElement newPath[] = new MenuElement[path.length+1];
                        System.arraycopy(path,0,newPath,0,path.length);
                        newPath[path.length] = ((JMenu)lastElement).getPopupMenu();
                        MenuSelectionManager.defaultManager().setSelectedPath(newPath);
                    } else if(lastElement instanceof JMenuItem) {
                        MenuSelectionManager.defaultManager().clearSelectedPath();
                        ((JMenuItem)lastElement).doClick(0);
                        ((JMenuItem)lastElement).setArmed(false);
                    }
                }
            }
        }
    }

    /**
     * Handle arrow down key in the popup menu. This code is borrowed
     * from swing.plaf.basic.BasicMenuUI
     */
    private class SelectNextItemAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            MenuElement currentSelection[] = MenuSelectionManager.defaultManager().getSelectedPath();
            if(currentSelection.length > 1) {
                MenuElement parent = currentSelection[currentSelection.length-2];
                if(parent.getComponent() instanceof JMenu) {
                    MenuElement childs[];
                    parent = currentSelection[currentSelection.length-1];
                    childs = parent.getSubElements();
                    if(childs.length > 0) {
                        MenuElement newPath[] = new MenuElement[currentSelection.length+1];
                        System.arraycopy(currentSelection,0,
                                         newPath,0,currentSelection.length);
                        newPath[currentSelection.length] = nextEnabledChild(childs,0);
                        if(newPath[currentSelection.length] != null)
                            MenuSelectionManager.defaultManager().setSelectedPath(newPath);
                    }
                } else {
                    MenuElement childs[] = parent.getSubElements();
                    MenuElement nextChild;
                    int i,c;
                    for(i=0,c=childs.length;i<c;i++) {
                        if(childs[i] == currentSelection[currentSelection.length-1]) {
                            nextChild = nextEnabledChild(childs,i+1);
                            if(nextChild == null)
                                nextChild = nextEnabledChild(childs,0);
                            if(nextChild != null) {
                                currentSelection[currentSelection.length-1] = nextChild;
                                MenuSelectionManager.defaultManager().setSelectedPath(currentSelection);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    /**
     * Handle arrow up key in the popup menu. This code is borrowed
     * from swing.plaf.basic.BasicMenuUI
     */
    private class SelectPreviousItemAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
        MenuElement currentSelection[] = MenuSelectionManager.defaultManager().getSelectedPath();
            if(currentSelection.length > 1) {
                MenuElement parent = currentSelection[currentSelection.length-2];
                if(parent.getComponent() instanceof JMenu) {
                    MenuElement childs[];
                    parent = currentSelection[currentSelection.length-1];
                    childs = parent.getSubElements();
                    if(childs.length > 0) {
                        MenuElement newPath[] = new MenuElement[currentSelection.length+1];
                        System.arraycopy(currentSelection,0,
                                         newPath,0,currentSelection.length);
                        newPath[currentSelection.length] = previousEnabledChild(childs,childs.length-1);
                        if(newPath[currentSelection.length] != null)
                            MenuSelectionManager.defaultManager().setSelectedPath(newPath);
                    }
                } else {
                    MenuElement childs[] = parent.getSubElements();
                    MenuElement nextChild;
                    int i,c;
                    for(i=0,c=childs.length;i<c;i++) {
                        if(childs[i] == currentSelection[currentSelection.length-1]) {
                            nextChild = previousEnabledChild(childs,i-1);
                            if(nextChild == null)
                                nextChild = previousEnabledChild(childs,childs.length-1);
                            if(nextChild != null) {
                                currentSelection[currentSelection.length-1] = nextChild;
                                MenuSelectionManager.defaultManager().setSelectedPath(currentSelection);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    /**
     * Used by SelectNextItemAction. This code is borrowed from
     * swing.plaf.basic.BasicMenuUI
     */
    private MenuElement nextEnabledChild(MenuElement e[],int fromIndex) {
        int i,c;
        for(i=fromIndex,c=e.length ; i < c ; i++) {
            if (e[i]!=null) {
                Component comp = e[i].getComponent();
                if(comp != null && comp.isEnabled())
                    return e[i];
            }
        }
        return null;
    }

    /**
     * Used by SelectPreviousItemAction. This code is borrowed from
     * swing.plaf.basic.BasicMenuUI
     */
    private MenuElement previousEnabledChild(MenuElement e[],int fromIndex) {
        int i;
        for(i=fromIndex ; i >= 0 ; i--) {
            if (e[i]!=null) {
                Component comp = e[i].getComponent();
                if(comp != null && comp.isEnabled())
                    return e[i];
            }
        }
        return null;
    }


    /**
     * Test the component
     */
    /*public static void main(String[] args) {
        JFrame f = new JFrame("PopupMenuButton Test");

        JMenu m = new JMenu("submenu");
        m.add( new JMenuItem("ItemA"));
        m.add( new JMenuItem("ItemB"));
        m.add( new JSeparator());
        m.add( new JMenuItem("ItemC"));

        JPopupMenu popup = new JPopupMenu();
        popup.add( new JMenuItem("Item1"));
        popup.add( new JMenuItem("Item2"));
        popup.add( new JSeparator());
        popup.add(m);
        PopupMenuButton b = new PopupMenuButton("Create", popup);
        f.getContentPane().setLayout(new FlowLayout());
        f.getContentPane().add(b);
        
        f.setBounds(300,300, 200,100);
        f.setVisible(true);
   }*/
}

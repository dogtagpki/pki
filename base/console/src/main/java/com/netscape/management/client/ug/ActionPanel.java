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

import java.awt.event.*;
import java.awt.*;

import javax.swing.*;
import com.netscape.management.client.util.JButtonFactory;
import com.netscape.management.nmclf.SuiLookAndFeel;


/**
 * ActionPanel manages the buttons on the right side for the ResourcePickerDlg.
 * These buttons are responsible for changing the user and group directory,
 * toggling between all available search interfaces, and finally performing the
 * search itself.
 *
 * @see ResourcePickerDlg
 * @see BasicPanel
 * @see AdvancePanel
 */
public class ActionPanel extends JPanel {

    PickerEditorResourceSet resource = new PickerEditorResourceSet();
    JButton _changeDirectoryButton;
    JButton _searchButton;
    JButton _methodButton;


    /**
     * Constructor which creates all buttons, including the method button
     * which allows the user to toggle between all available search
     * interfaces.
     *
     * @param parent  listener for the button action events
     */
    public ActionPanel(ActionListener parent) {
        this(parent, true);
    }


    /**
      * Constructor which creates at least two buttons. The method button
      * is only created if the second parameter is true.
      *
      * @param parent              listener for the button action events
      * @param createMethodButton  determines whether the method button should be created
      */
    public ActionPanel(ActionListener parent, boolean createMethodButton) {
        PickerEditorResourceSet resource = new PickerEditorResourceSet();
        setLayout(new BorderLayout(0, 0));

        JPanel panel = new JPanel();
        panel.setLayout(
                new GridLayout(4, 1, 0, SuiLookAndFeel.COMPONENT_SPACE));

        _changeDirectoryButton = JButtonFactory.create(
                resource.getString("ActionPanel", "changeDirButton"));
        _changeDirectoryButton.setToolTipText(resource.getString("ActionPanel", "changeDir_tt"));
        _changeDirectoryButton.addActionListener(parent);
        _changeDirectoryButton.setActionCommand("ChangeDir");
        panel.add(_changeDirectoryButton);

        JLabel blankLabel = new JLabel("");
        panel.add(blankLabel);

        _searchButton = JButtonFactory.create(
                resource.getString("ActionPanel", "searchButton"));
        _searchButton.setToolTipText(resource.getString("ActionPanel","search_tt"));
        _searchButton.addActionListener(parent);
        _searchButton.setActionCommand("Search");
        panel.add(_searchButton);

        if (createMethodButton == true) {
            _methodButton = JButtonFactory.create(
                    resource.getString("ActionPanel", "AdvancedButton"));
            _methodButton.setToolTipText(resource.getString("ActionPanel","Advanced_tt"));
            _methodButton.setActionCommand("SHOW:"+
                    _methodButton.getText());
            _methodButton.addActionListener(parent);
            panel.add(_methodButton);
        } else {
            _methodButton = null;
            JLabel blankLabel2 = new JLabel("");
            panel.add(blankLabel2);
        }

        add("North", panel);
    }


    /**
      * Adds a listener for the search button events.
      *
      * @param listener  the listener for the search button events
      */
    public void addActionListener(ActionListener listener) {
        _searchButton.addActionListener(listener);
    }


    /**
      * Sets the default focus for the carriage return key on the search
      * button. Called when the focus is set in the type-in field of
      * BasicPanel and AdvancedPanel. This satisfies a usability
      * requirement.
      */
    public void setDefaultButton() {
        _searchButton.getRootPane().setDefaultButton(_searchButton);
    }


    /**
      * Returns the search button.
      *
      * @return  the search button
      */
    public JButton getSearchButton() {
        return _searchButton;
    }


    /**
      * Enables and disables the search button.
      *
      * @param b  if true enable the search button; otherwise disable
      */
    public void setEnableSearch(boolean b) {
        _searchButton.setEnabled(b);
    }


    /**
      * Enables and disables the method button.
      *
      * @param b  if true enable the method button; otherwise disable
      */
    public void setEnableMethod(boolean b) {
        if (_methodButton != null) {
            _methodButton.setEnabled(b);
            _methodButton.setVisible(b);
        }
    }


    /**
      * Sets the text label for the method button, as well as the action
      * command so that the appropriate event handler will be invoked.
      *
      * @param sID      the action command ID
      * @param sMethod  the text label for the method button
      */
    public void setMethodButtonText(String sID, String sMethod) {
        _methodButton.setActionCommand("SHOW:"+sID);
        _methodButton.setText(sMethod);
        if (sMethod.equals(resource.getString("ActionPanel","AdvancedButton"))) {
            _methodButton.setToolTipText(resource.getString("ActionPanel","Advanced_tt"));
        } else if (sMethod.equals(resource.getString("ActionPanel","BasicButton"))) {
            _methodButton.setToolTipText(resource.getString("ActionPanel","Basic_tt"));
        } else {
            _methodButton.setToolTipText("");
        }
    }


    /**
      * Gets the text label for the method button.
      *
      * @return  the text label for the method button
      */
    public String getMethodButtonText() {
        return _methodButton.getText();
    }


    /**
      * Enables and disables the change directory button. Enabling also makes the
      * button visible, and disabling makes the button invisible.
      *
      * @param b  if true enable the change directory button; otherwise disable
      */
    public void setAllowChangeDirectory(boolean b) {
        _changeDirectoryButton.setVisible(b);
        _changeDirectoryButton.setEnabled(b);
    }


    /**
      * Sets the button width to the longest label.
      *
      * @param label  most recently added method text
      */
    public void updateMethodButtonWidth(String label) {
        JButton tmp = new JButton(label);
        JPanel panel = new JPanel();
        panel.add(tmp);
        panel.doLayout(); // Force the layout of the button.

        int width = tmp.getWidth();
        width = width + SuiLookAndFeel.BUTTON_SIZE_MULTIPLE -
                (width % SuiLookAndFeel.BUTTON_SIZE_MULTIPLE);
        if (width > _methodButton.getWidth()) {
            _methodButton.setPreferredSize(tmp.getSize());
            _methodButton.setMinimumSize(tmp.getSize());
        }
    }
}

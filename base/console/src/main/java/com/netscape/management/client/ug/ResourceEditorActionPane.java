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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.BorderLayout;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JPanel;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.JButtonFactory;
import com.netscape.management.nmclf.SuiLookAndFeel;


/**
 * This class sets up the default dialog action buttons
 * for the ResourceEditor. This class can be extended in order to
 * create different buttons for a specialized ResourceEditor.
 *
 * @version  %I%, %G%
 * @see      ResourceEditor
 */
public class ResourceEditorActionPane extends JPanel {

    private ResourceSet _resource;
    private JButton _advancedButton;


    /**
     * Constructor creates the dialog action buttons for the ResourceEditor
     * dialog. By default, the advanced button is disabled.
     *
     * @param parent  the ActionListener for the buttons
     */
    public ResourceEditorActionPane(ActionListener parent) {
        _resource = new ResourceSet("com.netscape.management.client.ug.PickerEditorResource");

        // Create the buttons
        _advancedButton = new JButton(_resource.getString("", "advancedButton"));
        _advancedButton.setActionCommand("advanced");
        _advancedButton.addActionListener(parent);
        enableAdvanced(false); // by default, disable the advanced button.

        JButton ok = new JButton(_resource.getString("", "okButton"));
        ok.setActionCommand("Ok");
        ok.addActionListener(parent);

        JButton cancel = new JButton(_resource.getString("", "cancelButton"));
        cancel.setActionCommand("Cancel");
        cancel.addActionListener(parent);

        JButton help = new JButton(_resource.getString("", "helpButton"));
        help.setActionCommand("help");
        help.addActionListener(parent);

        // Resize the buttons according to UI spec
        JButtonFactory.resize(_advancedButton);
        JButtonFactory.resize(cancel);
        JButtonFactory.resize(cancel, ok); // same size as cancel
        JButtonFactory.resize(cancel, help); // same size as cancel

        JPanel p = new JPanel();
        p.setLayout(new GridBagLayout());
        GridBagUtil.constrain(p, _advancedButton, 0, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.EAST, GridBagConstraints.NONE,
                0, 0, 0, SuiLookAndFeel.SEPARATED_COMPONENT_SPACE*4);
        GridBagUtil.constrain(p, ok, 1, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.NONE, 0,
                0, 0, SuiLookAndFeel.COMPONENT_SPACE);
        GridBagUtil.constrain(p, cancel, 2, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.NONE, 0,
                0, 0, SuiLookAndFeel.SEPARATED_COMPONENT_SPACE);
        GridBagUtil.constrain(p, help, 3, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.NONE, 0,
                0, 0, 0);

        setLayout(new BorderLayout());
        add(p , BorderLayout.EAST);
    }


    /**
      * Enables or disables the advanced button.
      *
      * @param state  the new state for the advanced button
      */
    public void enableAdvanced(boolean state) {
        _advancedButton.setEnabled(state);
        _advancedButton.setVisible(state);
    }


    /**
      * Customizes the label for the advanced button.
      *
      * @param label  the new label for the advanced button
      */
    public void setAdvancedText(String label) {
        _advancedButton.setText(label);
        JButtonFactory.resize(_advancedButton);
    }
}

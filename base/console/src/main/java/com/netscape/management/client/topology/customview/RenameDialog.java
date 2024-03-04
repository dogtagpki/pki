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
package com.netscape.management.client.topology.customview;

import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.topology.*;
import com.netscape.management.client.util.*;

/**
 * Dialog for rename a custom view
 */
public class RenameDialog extends AbstractDialog implements SwingConstants,
SuiConstants {
    JTextField _textField = new JTextField(22);
	ViewInfo[] _viewInfoArray;
	Frame _frame;
	String _originalName;

    static String i18n(String id) {
        return TopologyInitializer._resource.getString("customview", id);
    }

    /**
      * constructor
      *
      * @param frame parent frame
      * @param name name of the custom view
      */
    public RenameDialog(Frame frame, String name, ViewInfo[] viewInfoArray) {
        super(frame, i18n("RenameView"), true, OK | CANCEL | HELP,
                HORIZONTAL_BUTTONS);
        _textField.setText(name);
		_frame = frame;
		_viewInfoArray = viewInfoArray;
		_originalName = name;
        createDialogPanel();
    }

    /**
      * show the dialog modally
      */
    public void showModal() {
        setMinimumSize(getSize());
        setVisible(true);
    }

    /**
      * create dialog internal controls.
      */
    protected void createDialogPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());

        JLabel viewLabel = new JLabel(i18n("NewViewName"));
        viewLabel.setLabelFor(_textField);
        GridBagUtil.constrain(panel, viewLabel, 0, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 3, 0);

        GridBagUtil.constrain(panel, _textField, 0, 1, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 3, 0);
        setFocusComponent(_textField);
        enableOK();
        _textField.getDocument().addDocumentListener(
                new ChangeEventListener());
        setPanel(panel);
    }

    /**
      * return the new custom view name
      */
    public String getResult() {
        return _textField.getText();
    }

    /**
      * enable okay if the new name field is changed.
      */
    private void enableOK() {
        String s = _textField.getText().trim();
        boolean enable = (s.length() > 0);
        setOKButtonEnabled(enable);
    }

    /**
      * inner class to notify for text field change
      */
    class ChangeEventListener implements DocumentListener {
        /**
          * set the okay button status if the text field is changed
          */
        public void insertUpdate(DocumentEvent e) {
            enableOK();
        }

        /**
          * set the okay button status if the text field is changed
          */
        public void removeUpdate(DocumentEvent e) {
            enableOK();
        }

        /**
          * set the okay button status if the text field is changed
          */
        public void changedUpdate(DocumentEvent e) {
            enableOK();
        }
    }

    /**
      * Called when HELP button is pressed
      */
    protected void helpInvoked() {
        Help help = new Help(TopologyInitializer._resource);
        help.contextHelp("customview", "RenameDialogHelp");
    }
	
    /**
      * Called when OK button is pressed
      */
    protected void okInvoked() {
		boolean isDuplicate = false;
		if(_viewInfoArray != null)
		{
			for(int i=0; i < _viewInfoArray.length; i++)
			{
				if(_viewInfoArray[i].getDisplayName().equalsIgnoreCase(getResult()) &&
					!_originalName.equals(getResult()))
				{
					isDuplicate = true;
					break;
				}
			}
		}
		if(isDuplicate)
		{
			JOptionPane.showMessageDialog(_frame, 
									i18n("NameExistsMsg"), 
									i18n("NameExistsTitle"), 
									JOptionPane.ERROR_MESSAGE);
		}
		else
		{
			super.okInvoked();
		}
    }
}

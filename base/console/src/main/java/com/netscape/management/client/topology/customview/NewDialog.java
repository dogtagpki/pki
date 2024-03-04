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
 * dialog for creating new custom view
 */
public class NewDialog extends AbstractDialog implements SwingConstants,
SuiConstants {
    JTextField _textField = new JTextField(22);
	ViewInfo[] _viewInfoArray;
	Frame _frame;

    static String i18n(String id) {
        return TopologyInitializer._resource.getString("customview", id);
    }

    /**
      * constructor
      *
      * @param frame parent frame
      */
    public NewDialog(Frame frame, ViewInfo[] viewInfoArray) {
        super(frame, i18n("NewView"), true, OK | CANCEL | HELP,
                HORIZONTAL_BUTTONS);
        createDialogPanel();
		_frame = frame;
		_viewInfoArray = viewInfoArray;
    }

    /**
      * show the dialog
      */
    public void showModal() {
        setMinimumSize(getSize());
        setVisible(true);
    }

    /**
      * create the dialog content
      */
    protected void createDialogPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());

        JLabel viewLabel = new JLabel(i18n("ViewName"));
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
      * return the name of the new custom view
      *
      * @return name of the new custom view
      */
    public String getResult() {
        return _textField.getText();
    }

    /**
      * enable okay if the custom view name is longer than 0
      */
    private void enableOK() {
        String s = _textField.getText().trim();
        boolean enable = (s.length() > 0);
        setOKButtonEnabled(enable);
    }

    /**
      * inner class for event change
      */
    class ChangeEventListener implements DocumentListener {
        /**
          * update the ok button whenever the textfield is changed
          *
          * @param e document event
          */
        public void insertUpdate(DocumentEvent e) {
            enableOK();
        }

        /**
          * update the ok button whenever the textfield is changed
          *
          * @param e document event
          */
        public void removeUpdate(DocumentEvent e) {
            enableOK();
        }

        /**
          * update the ok button whenever the textfield is changed
          *
          * @param e document event
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
        help.contextHelp("customview", "NewDialogHelp");
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
				if(_viewInfoArray[i].getDisplayName().equalsIgnoreCase(getResult()))
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

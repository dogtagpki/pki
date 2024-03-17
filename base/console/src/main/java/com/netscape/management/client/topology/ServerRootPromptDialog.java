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

package com.netscape.management.client.topology;

import java.awt.*;
import javax.swing.*;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;
import javax.swing.text.Document;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 * Dialog which prompts for the old server root for migration.
 *
 * @author  phlee
 */

public class ServerRootPromptDialog extends AbstractModalDialog implements SuiConstants {
    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");

    private JTextField _serverRoot; // will contain the server root specified by user
    private String _revertServerRoot;
    private Document _serverRootDoc;
    private Help _helpSession; // support for help.


    /**
     * constructor for the dialog
     */
    public ServerRootPromptDialog(Frame parent) {
        // This is a modal dialog to support synchronous processing, i.e.,
        // usage involves displaying the dialog, user interacting with the
        // dialog, and the code retrieving the data from the dialog before
        // continuing.
        super(parent, _resource.getString("ServerRootPromptDialog", "Title"));
        setOKButtonEnabled(false);

        _helpSession = new Help(_resource);

        JLabel prompt = new JLabel(
                _resource.getString("ServerRootPromptDialog", "Prompt"));
        JLabel textFieldLabel = new JLabel(
                _resource.getString("ServerRootPromptDialog", "TextFieldLabel"));
        _serverRoot = new SingleByteTextField(32);
        prompt.setLabelFor(_serverRoot);
        _serverRootDoc = _serverRoot.getDocument();
        _serverRootDoc.addDocumentListener(new DialogDocumentListener());
        setFocusComponent(_serverRoot); // Set the component to get the focus
        //JLabel blankLabel = new JLabel(""); // Need this to keep the panel from centering

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(panel, prompt, 0, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(panel, _serverRoot, 1, 2,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 3, 0);

        setMinimumSize(getPreferredSize());
        setPanel(panel);
    }


    /**
      * The deprecation warning for this is erroneous. This method
      * overrides Dialog.show(). It is safe to ignore warning.
      */
    public void show() {
        prepareForRevert();
        ModalDialogUtil.setDialogLocation(this, null);
        super.show();
    }


    public String getServerRoot() {
        return _serverRoot.getText();
    }


    /**
      * Need to revert in addition to what the super does.
      */
    public void cancelInvoked() {
        revert();
        super.cancelInvoked();
    }


    /**
      * Implements the method to handle help event.
      */
    public void helpInvoked() {
        _helpSession.contextHelp("topology", "srpd");
    }


    private void revert() {
        _serverRoot.setText(_revertServerRoot);
    }


    private void prepareForRevert() {
        _revertServerRoot = _serverRoot.getText();
    }


    /**
      * Inner class used to handle JTextField change events.
      */
    class DialogDocumentListener implements DocumentListener {
        public void insertUpdate(DocumentEvent e) {
            myUpdate(e);
        }

        public void removeUpdate(DocumentEvent e) {
            myUpdate(e);
        }

        public void changedUpdate(DocumentEvent e) {
            myUpdate(e);
        }

        public void myUpdate(DocumentEvent e) {
            if (_serverRoot.getText().equals("")) {
                ServerRootPromptDialog.this.setOKButtonEnabled(false);
            } else {
                ServerRootPromptDialog.this.setOKButtonEnabled(true);
            }
        }
    }
}

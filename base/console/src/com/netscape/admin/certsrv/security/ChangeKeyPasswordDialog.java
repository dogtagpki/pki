// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.admin.certsrv.security;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import javax.swing.*;
import java.awt.*;

/**
 *
 * Change A Key Pair File Password
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
public class ChangeKeyPasswordDialog extends AbstractDialog {

    KeyCertTaskInfo taskInfo;
    ConsoleInfo _consoleInfo;

    String oldPasswdLabel;
    String newPasswdLabel;
    String confirmPasswdLabel;

    //create password field with default width of 20 characters
    SingleBytePasswordField oldPasswd = new SingleBytePasswordField(20);
    SingleBytePasswordField newPasswd = new SingleBytePasswordField(20);
    SingleBytePasswordField confirmPasswd = new SingleBytePasswordField(20);

    ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.ChangeKeyPasswordDialogResource");

    /**
     * Called when OK button is pressed, and start the password change process
     *
     */
    protected void okInvoked() {

        taskInfo = new KeyCertTaskInfo(_consoleInfo);
        taskInfo.clear();
        taskInfo.put("sie", KeyCertUtility.createTokenName(_consoleInfo));
        taskInfo.put("oldkfpw", oldPasswd.getText());
        taskInfo.put("keyfilepw", newPasswd.getText());
        taskInfo.put("keyfilepwv", confirmPasswd.getText());

        if (!KeyCertUtility.validPassword(newPasswd.getText(),
                confirmPasswd.getText(), _consoleInfo)) {
            return;
        }
        Response response = null;
        try {
            response = taskInfo.exec(taskInfo.SEC_CHANGEPW);
        } catch (Exception e) {
            SuiOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(), e.getMessage());
            return;
        }

        try {
            MessageDialog.messageDialog(
                    (Message)(response.getMessages().elementAt(0)));
        } catch (Exception ex) {}

        if (((Message)(response.getMessages().elementAt(0))).getStatus()
                == Message.NMC_SUCCESS)
            super.okInvoked();
    }

    /**
      * Called when HELP button is pressed, invoke online help
      */
    protected void helpInvoked() {
        Help help = new Help(resource);
        help.help("ChangeKeyPasswordDialog", "help");
    }


    private JLabel createRightAlignLabel(String label) {
        return new JLabel(label, JLabel.RIGHT);
    }

    private JPanel getPasswdPane() {
        JPanel passwdPane = new JPanel();
        passwdPane.setLayout(new GridBagLayout());
        int y = 0;

        GridBagUtil.constrain(passwdPane,
                createRightAlignLabel(
                resource.getString("ChangeKeyPasswordDialog",
                "oldPasswdLabel")), 0, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                SEPARATED_COMPONENT_SPACE, 0, COMPONENT_SPACE,
                COMPONENT_SPACE);

        GridBagUtil.constrain(passwdPane, oldPasswd, 1, y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, SEPARATED_COMPONENT_SPACE, 0,
                COMPONENT_SPACE, 0);

        GridBagUtil.constrain(passwdPane,
                createRightAlignLabel(
                resource.getString("ChangeKeyPasswordDialog",
                "newPasswdLabel")), 0, ++y, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, COMPONENT_SPACE);

        GridBagUtil.constrain(passwdPane, newPasswd, 1, y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(passwdPane,
                createRightAlignLabel(
                resource.getString("ChangeKeyPasswordDialog",
                "confirmPasswdLabel")), 0, ++y, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, COMPONENT_SPACE);

        GridBagUtil.constrain(passwdPane, confirmPasswd, 1, y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        return passwdPane;
    }


    /**
      * Create a dialog with 3 password field, for changing
      * trust db password.
      *
      * @param consoleInfo Console information
      *
      */
    public ChangeKeyPasswordDialog(ConsoleInfo consoleInfo) {
        super(null, "", true, OK | CANCEL | HELP);

        _consoleInfo = consoleInfo;

        JPanel pane = new JPanel();
        pane.setLayout(new BorderLayout());

        //add some space between the explain text and the password prompt
        //pane.add(Box.createRigidArea(new Dimension(0, SEPARATED_COMPONENT_SPACE)));

        //add the password pane
        pane.add("Center", getPasswdPane());

        getContentPane().add(pane);
        setTitle(resource.getString("ChangeKeyPasswordDialog", "explainText"));

        pack();
        show();
    }

    /*public static void main(String arg[]) {
     ChangeKeyPasswordDialog c = (new ChangeKeyPasswordDialog(new ConsoleInfo()));
     }*/

}

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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class CreateTrustPane extends JPanel implements SuiConstants, IKeyCertPage {

    SingleBytePasswordField _passwd = new SingleBytePasswordField(20);
    SingleBytePasswordField _confirmPasswd =
            new SingleBytePasswordField(20);
    JLabel _selectedToken = new JLabel();

    JLabel _passwdLabel;
    JLabel _tokenLabel;
    JLabel _confirmPasswdLabel;

    IWizardControl control;

    String _noNeedToRequestInstallCert;

    public JPanel getPanel() {
        return this;
    }

    public boolean pageShow(WizardObservable observable) {
        boolean show = false;

        ((StatusPane)(observable.get("statusPane"))).setShow(false);
        if (((Boolean)(observable.get("createTrust"))).booleanValue()) {
            show = true;

            if ((_passwd.getText().length() == 0) ||
                    (_confirmPasswd.getText().length() == 0)) {
                control = (IWizardControl)(observable.get("Wizard"));
                control.setCanGoForward(false);
            }

            _selectedToken.setText((String)(observable.get("sie")));
        } else if (((Boolean)(observable.get("noneed"))).booleanValue()) {
            StatusPane statusPane = (StatusPane)(observable.get("statusPane"));
            statusPane.setMessage(_noNeedToRequestInstallCert);
            statusPane.setShow(true);
            statusPane.setLastPage(true);

            ((IWizardControl)(observable.get("Wizard"))).setIsLastPage(
                    true);
        }

        return show;
    }

    public boolean pageHide(WizardObservable observable) {
        boolean hide = false;

        String dbName = (String)(observable.get("sie"));

        if (!KeyCertUtility.validPassword(_passwd.getText(),
                _confirmPasswd.getText(), (observable.getConsoleInfo()))) {
            hide = false;
        } else if ( (_passwd.getText().equals(_confirmPasswd.getText())) &&
                (!(dbName.equals("")))) {
            KeyCertTaskInfo taskInfo =
                    ((WizardObservable) observable).getTaskInfo();
            taskInfo.put("alias", dbName);
            taskInfo.put("keyfilepw", _confirmPasswd.getText());
            observable.put("keyPasswd", _confirmPasswd.getText());
            try {
                taskInfo.exec(taskInfo.SEC_TRUST);
            } catch (Exception e) {
                SuiOptionPane.showMessageDialog(
                        UtilConsoleGlobals.getActivatedFrame(),
                        e.getMessage());
                return false;
            }


            //MessageDialog.messageDialog((Message)(taskInfo.getResponse().getMessages().elementAt(0)));
            StatusPane statusPane = (StatusPane)(observable.get("statusPane"));
            statusPane.setMessage( (Message)
                    (taskInfo.getResponse().getMessages().elementAt(0)));
            statusPane.setShow(true);

            if (((Message)
                    (taskInfo.getResponse().getMessages().elementAt(0))
                    ).getStatus() == Message.NMC_SUCCESS) {
                hide = true;
                observable.put("createTrust", new Boolean(false));

                if (((Boolean)(observable.get("noneed"))).booleanValue()) {
                    statusPane.appendMessage("\n\n"+
                            _noNeedToRequestInstallCert);
                    statusPane.setLastPage(true);
                    ((IWizardControl)(observable.get("Wizard"))).
                            setIsLastPage(true);
                }
            }
        }

        return hide;
    }


    class KeyActionListener implements KeyListener {
        public void keyTyped(KeyEvent e) {}
        public void keyPressed(KeyEvent e) {}
        public void keyReleased(KeyEvent e) {
            if (_passwd.getText().length() > 0) {
                control.setCanGoForward(true);
            } else {
                control.setCanGoForward(false);
            }
        }
    }

    private JPanel getPasswdPane() {
        JPanel passwdPane = new JPanel();
        passwdPane.setLayout(new GridBagLayout());
        int y = 0;


        GridBagUtil.constrain(passwdPane, _tokenLabel, 0, ++y, 1, 1,
                0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);


        GridBagUtil.constrain(passwdPane, _selectedToken, 1, y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, DIFFERENT_COMPONENT_SPACE,
                COMPONENT_SPACE, 0);

        GridBagUtil.constrain(passwdPane, _passwdLabel, 0, ++y, 1, 1,
                0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        _passwd.addKeyListener(new KeyActionListener());
        GridBagUtil.constrain(passwdPane, _passwd, 1, y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, DIFFERENT_COMPONENT_SPACE,
                COMPONENT_SPACE, 0);

        GridBagUtil.constrain(passwdPane, _confirmPasswdLabel, 0, ++y,
                1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        _confirmPasswd.addKeyListener(new KeyActionListener());
        GridBagUtil.constrain(passwdPane, _confirmPasswd, 1, y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, DIFFERENT_COMPONENT_SPACE,
                COMPONENT_SPACE, 0);

        return passwdPane;
    }

    public CreateTrustPane() {
        super();
        setLayout(new GridBagLayout());

        ResourceSet resource = KeyCertUtility.getKeyCertWizardResourceSet();
        _passwdLabel = new JLabel(
                resource.getString("CreateTrustPane", "passwdLabel"),
                JLabel.RIGHT);
        _tokenLabel = new JLabel(
                resource.getString("CreateTrustPane", "tokenLabel"),
                JLabel.RIGHT);
        _confirmPasswdLabel = new JLabel(
                resource.getString("CreateTrustPane", "confirmPasswdLabel"),
                JLabel.RIGHT);

        _noNeedToRequestInstallCert =
                resource.getString("CreateTrustPane", "noNeedToRequestInstallCert");


        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("CreateTrustPane", "title")));

        int y = 0;

        GridBagUtil.constrain(this,
                new MultilineLabel(
                resource.getString("CreateTrustPane", "explain")), 0,
                ++y, 1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, getPasswdPane(), 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(), 0, ++y,
                1, 1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(this,
                new JLabel(
                resource.getString(null, "clickNextToContinue")), 0,
                ++y, 1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.getContentPane().add("North", new CreateTrustPane());
     f.setSize(400,400);
     f.show();
     }*/

}

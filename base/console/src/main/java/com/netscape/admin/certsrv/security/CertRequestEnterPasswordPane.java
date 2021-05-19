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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.Enumeration;
import java.util.Hashtable;

import javax.swing.Box;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;

import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.IWizardControl;
import com.netscape.management.client.util.MultilineLabel;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.SingleBytePasswordField;
import com.netscape.management.client.util.UtilConsoleGlobals;
import com.netscape.management.nmclf.SuiConstants;

class CertRequestEnterPasswordPane extends JPanel implements SuiConstants,
IKeyCertPage {


    JLabel _passwdLabel;
    JLabel _tokenLabel;

    JLabel _selectedToken = new JLabel();
    SingleBytePasswordField _passwd = new SingleBytePasswordField(20);

    IWizardControl control;
    boolean modified = false;

    @Override
    public JPanel getPanel() {
        return this;
    }

    @Override
    public boolean pageShow(WizardObservable observable) {
        boolean show =
                ((Boolean)(observable.get("requestCert"))).booleanValue();
        if (show) {
            _passwd.setText((String)(observable.get("keyPasswd")));
            control = (IWizardControl)(observable.get("Wizard"));
            if (_passwd.getText().length() == 0) {
                control.setCanGoForward(false);
            }

            boolean isInternal = ((Boolean)(observable.get("isInternal"))).
                    booleanValue();

            _selectedToken.setText((String)(observable.get("tokenName")));
        }

        return show;
    }

    @Override
    public boolean pageHide(WizardObservable observable) {
        boolean hide = true;
        KeyCertTaskInfo taskInfo = observable.getTaskInfo();

        if (modified || ((Boolean)(observable.get("CertReqModified"))).
                booleanValue()) {
            observable.put("CertReqModified", Boolean.valueOf(true));
            Hashtable<String, Object> param = (Hashtable<String, Object>)(observable.get("CertReqCGIParam"));
            //param.put("alias"     , ((Boolean)(observable.get("isInternal"))).booleanValue()?observable.get("sie"):observable.get("tokenName"));
            param.put("alias" , observable.get("sie"));

            param.put("keyfilepw" , _passwd.getText());
            observable.put("keyPasswd", _passwd.getText());


            Enumeration<String> cgiParam = param.keys();
            while (cgiParam.hasMoreElements()) {
                String key = cgiParam.nextElement();
                taskInfo.put(key, param.get(key));
            }

            Response response = null;

            try {
                response = taskInfo.exec(KeyCertTaskInfo.SEC_GCRT);
                taskInfo.clear();
            } catch (Exception e) {
                JOptionPane.showMessageDialog(
                        UtilConsoleGlobals.getActivatedFrame(),
                        e.getMessage());
                hide = false;
            }

            if (!response.hasCert()) {
                //MessageDialog.messageDialog((Message)(taskInfo.getResponse().getMessages().elementAt(0)));
                StatusPane statusPane = (StatusPane)(observable.get("statusPane"));
                statusPane.setMessage(taskInfo.getResponse().getMessages().elementAt(0));
                statusPane.setShow(true);
                modified = true;
            } else {
                observable.put("CertReq",
                        response.getMessages().elementAt(0).getExtraMessage());
                observable.put("CertReqModified", Boolean.valueOf(false));
                modified = false;

                //Need this inorder to know if a new request has been issued, so
                //request via url can execute again
                observable.put("newCertReq", Boolean.valueOf(true));
            }


        }
        return hide;
    }

    class KeyActionListener implements KeyListener {
        @Override
        public void keyTyped(KeyEvent e) {}
        @Override
        public void keyPressed(KeyEvent e) {}
        @Override
        public void keyReleased(KeyEvent e) {
            if (_passwd.getText().length() > 0) {
                control.setCanGoForward(true);
            } else {
                control.setCanGoForward(false);
            }
            modified = true;
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


        return passwdPane;
    }

    public CertRequestEnterPasswordPane() {
        super();
        setLayout(new GridBagLayout());

        ResourceSet resource = KeyCertUtility.getKeyCertWizardResourceSet();

        _passwdLabel = new JLabel(
                resource.getString("CertRequestEnterPasswordPane",
                "passwdLabel"), JLabel.RIGHT);
        _tokenLabel = new JLabel(
                resource.getString("CertRequestEnterPasswordPane",
                "tokenLabel"), JLabel.RIGHT);


        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("CertRequestEnterPasswordPane", "title")));

        int y = 0;


        GridBagUtil.constrain(this,
                new MultilineLabel(
                resource.getString("CertRequestEnterPasswordPane",
                "explain")), 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, DIFFERENT_COMPONENT_SPACE, 0);

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
     f.getContentPane().setLayout(new BorderLayout());
     f.getContentPane().add("Center", new CertRequestEnterPasswordPane());
     f.setSize(400,400);
     f.show();
     }*/

}

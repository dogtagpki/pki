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
import java.util.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class CertInstallTypePane extends JPanel implements SuiConstants,
IKeyCertPage {

    JRadioButton thisServer;
    JRadioButton certChain;
    JRadioButton ca;

    JLabel tokenName = new JLabel();
    SingleBytePasswordField passwd = new SingleBytePasswordField(20);
    JLabel certName = new JLabel();

    JLabel _certnameLabel;
    JLabel _tokenLabel;
    JLabel _certType;
    JLabel _passwordLabel;

    public static Hashtable param = new Hashtable();

    IWizardControl control;
    boolean modified = true;

    public JPanel getPanel() {
        return this;
    }

    public boolean pageShow(WizardObservable observable) {
        boolean show =
                ((Boolean)(observable.get("installCert"))).booleanValue();

        control = (IWizardControl)(observable.get("Wizard"));

        passwd.setText((String)(observable.get("keyPasswd")));
        if (passwd.getText().length() == 0) {
            control = (IWizardControl)(observable.get("Wizard"));
            setEnableNextButton();
        }

        if (show) {
            tokenName.setText((String)(observable.get("tokenName")));
            certName.setText((String)(observable.get("certName")));
        }

        return show;
    }

    public boolean pageHide(WizardObservable observable) {


        if (modified) {
            observable.put("keyfilepw", passwd.getText());

            observable.put("CertInstModified", new Boolean(true));

            param.put("certtype" ,
                    thisServer.isSelected() ? "0":
                    (certChain.isSelected() ? "1":"2"));
            param.put("alias" , observable.get("sie"));
            param.put("keyfilepw", passwd.getText());
            observable.put("keyPasswd", passwd.getText());

            if (thisServer.isSelected()) {
                param.put("certname", (String)(observable.get("certName")));
            } else {
                param.remove("certname");
            }

            modified = false;
        }

        return true;
    }

    void setEnableNextButton() {
        if (passwd.getText().length() == 0) {
            control.setCanGoForward(false);
        } else {
            control.setCanGoForward(true);
        }
    }

    class TypeActionListener implements ActionListener, KeyListener {
        public void keyTyped(KeyEvent e) {}
        public void keyPressed(KeyEvent e) {}
        public void keyReleased(KeyEvent e) {
            modified = true;
            setEnableNextButton();
        }

        public void actionPerformed(ActionEvent event) {
            modified = true;

            if (thisServer.isSelected()) {
                certName.setVisible(true);
                _certnameLabel.setVisible(true);

                _passwordLabel.setVisible(true);
                passwd.setVisible(true);

                setEnableNextButton();
            } else {
                certName.setVisible(false);
                _certnameLabel.setVisible(false);

                _passwordLabel.setVisible(false);
                passwd.setVisible(false);

                control.setCanGoForward(true);
            }
        }
    }



    private JPanel getCertTypePane() {
        JPanel certTypePane = new JPanel();
        certTypePane.setLayout(new GridBagLayout());
        int y = 0, x = 0;

        TypeActionListener listener = new TypeActionListener();
        thisServer.addActionListener(listener);
        certChain.addActionListener(listener);
        ca.addActionListener(listener);
        passwd.addKeyListener(listener);

        GridBagUtil.constrain(certTypePane,
                Box.createRigidArea(
                new Dimension(DIFFERENT_COMPONENT_SPACE, 0)), x, y, 1,
                1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(certTypePane, new JLabel("1.  "), ++x,
                ++y, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.NONE, 0, 0, 0, 0);

        GridBagUtil.constrain(certTypePane, _certType, ++x, y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(certTypePane, thisServer, x, ++y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(certTypePane, certChain, x, ++y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(certTypePane, ca, x, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        return certTypePane;
    }



    private JLabel createRightAlignLabel(String label) {
        return new JLabel(label, JLabel.RIGHT);
    }


    private JPanel getTokenInfoPane() {
        JPanel tokenInfoPane = new JPanel();
        tokenInfoPane.setLayout(new GridBagLayout());
        int y = 0;


        GridBagUtil.constrain(tokenInfoPane, _tokenLabel, 0, y, 1, 1,
                0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(tokenInfoPane, tokenName, 1, y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, DIFFERENT_COMPONENT_SPACE,
                COMPONENT_SPACE, 0);

        GridBagUtil.constrain(tokenInfoPane, _passwordLabel, 0, ++y, 1,
                1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(tokenInfoPane, passwd, 1, y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, DIFFERENT_COMPONENT_SPACE,
                COMPONENT_SPACE, 0);

        GridBagUtil.constrain(tokenInfoPane, _certnameLabel, 0, ++y, 1,
                1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(tokenInfoPane, certName, 1, y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, COMPONENT_SPACE,
                COMPONENT_SPACE, 0);

        return tokenInfoPane;
    }


    public CertInstallTypePane() {
        super();
        setLayout(new GridBagLayout());

        ResourceSet resource = KeyCertUtility.getKeyCertWizardResourceSet();
        thisServer = new JRadioButton(
                resource.getString("CertInstallTypePane",
                "thisServerLabel"), true);
        certChain = new JRadioButton(
                resource.getString("CertInstallTypePane",
                "certChainLabel"), false);
        ca = new JRadioButton(
                resource.getString("CertInstallTypePane", "caLabel"),
                false);

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(thisServer);
        buttonGroup.add(certChain);
        buttonGroup.add(ca);


        _certnameLabel =
                new JLabel(resource.getString("CertInstallTypePane", "certnameLabel"));
        _tokenLabel = createRightAlignLabel(
                resource.getString("CertInstallTypePane", "tokenLabel"));
        _certType =
                new JLabel(resource.getString("CertInstallTypePane", "certType"));
        _passwordLabel = createRightAlignLabel(
                resource.getString("CertInstallTypePane", "passwordLabel"));

        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("CertInstallTypePane", "title")));

        int y = 0;

        GridBagUtil.constrain(this, getCertTypePane(), 0, ++y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this,
                new JLabel(
                resource.getString("CertInstallTypePane", "promptPasswd"))
                , 0, ++y, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.NONE, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, getTokenInfoPane(), 0, ++y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
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
     f.getContentPane().add("North", new CertInstallTypePane());
     f.setSize(400,400);
     f.show();
     }*/

}

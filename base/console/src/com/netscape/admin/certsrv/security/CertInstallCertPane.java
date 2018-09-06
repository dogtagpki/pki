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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.Enumeration;

import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;

import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.IWizardControl;
import com.netscape.management.client.util.MultilineLabel;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.UITools;
import com.netscape.management.client.util.UtilConsoleGlobals;
import com.netscape.management.nmclf.SuiConstants;
import com.netscape.management.nmclf.SuiOptionPane;

class CertInstallCertPane extends JPanel implements SuiConstants,
IKeyCertPage {

    JRadioButton certInFile;
    JTextField certFilename = new JTextField(20);
    JRadioButton certInText;
    JTextArea certText = new JTextArea(7, 10);
    JButton paste;

    IWizardControl control = null;
    boolean modified = false;

    public JPanel getPanel() {
        return this;
    }

    public boolean pageShow(WizardObservable observable) {

        if (control == null) {
            control = (IWizardControl)(observable.get("Wizard"));
            setEnableNextButton();
        }

        return ((Boolean)(observable.get("installCert"))).booleanValue();
    }

    public boolean pageHide(WizardObservable observable) {
        boolean hide = true;

        if (modified) {
            observable.put("CertInstModified", new Boolean(true));
            modified = false;
        }

        if (((Boolean)(observable.get("CertInstModified"))).booleanValue()) {
            CertInstallTypePane.param.put("inputtype" ,
                    certInFile.isSelected() ? "0":"1");
            CertInstallTypePane.param.put("cert_file",
                    certFilename.getText());
            CertInstallTypePane.param.put("cert_txt" , certText.getText());
            CertInstallTypePane.param.put("tokenName", observable.get("tokenName"));

            KeyCertTaskInfo taskInfo = observable.getTaskInfo();
            Enumeration<String> cgiParam = CertInstallTypePane.param.keys();
            while (cgiParam.hasMoreElements()) {
                String key = cgiParam.nextElement();
                taskInfo.put(key, CertInstallTypePane.param.get(key));
            }

            Response response = null;
            try {
                response = taskInfo.exec(KeyCertTaskInfo.SEC_ICRT);
                taskInfo.clear();
            } catch (Exception e) {
                SuiOptionPane.showMessageDialog(
                        UtilConsoleGlobals.getActivatedFrame(),
                        e.getMessage());
                hide = false;
            }

            if (response.hasCertInstInfo() && response.hasCertInfo()) {
                observable.put("certInstInfo", response.getCertInstInfo());
                observable.put("certInfo", response.getCertInfo());
                observable.put("CertInstModified", new Boolean(false));
            } else {
                //hide = false;
                //MessageDialog.messageDialog((Message)(taskInfo.getResponse().getMessages().elementAt(0)));
                StatusPane statusPane = (StatusPane)(observable.get("statusPane"));

                statusPane.setMessage(taskInfo.getResponse().getMessages().elementAt(0));
                statusPane.setShow(true);
            }
        }

        return hide;
    }


    class CertPaneActionListener implements ActionListener, KeyListener {
        public void keyTyped(KeyEvent e) {}
        public void keyPressed(KeyEvent e) {}
        public void keyReleased(KeyEvent e) {
            setEnableNextButton();
        }

        public void actionPerformed(ActionEvent event) {
            modified = true;

            if (event.getActionCommand().equals("PASTE")) {
                certText.paste();
            }

            setEnableNextButton();
        }
    }

    void setEnableNextButton() {
        if ((certInFile.isSelected() &&
                (certFilename.getText().length() != 0)) ||
                (certInText.isSelected() &&
                (certText.getText().length() != 0))) {
            control.setCanGoForward(true);
        } else {
            control.setCanGoForward(false);
        }

        if (certInFile.isSelected()) {
            certText.setEnabled(false);
            certFilename.setEnabled(true);
        } else {
            certText.setEnabled(true);
            certFilename.setEnabled(false);
        }
    }


    public CertInstallCertPane() {
        super();
        setLayout(new GridBagLayout());

        ResourceSet resource = KeyCertUtility.getKeyCertWizardResourceSet();

        certInFile = new JRadioButton(
                resource.getString("CertInstallCertPane",
                "certInFileLabel"), false);
        certInText = new JRadioButton(
                resource.getString("CertInstallCertPane",
                "certInTextLabel"), true);
        paste = new JButton(resource.getString("CertInstallCertPane", "pasteLabel"));

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(certInFile);
        buttonGroup.add(certInText);

        int y = 0;

        CertPaneActionListener listener = new CertPaneActionListener();
        certFilename.addKeyListener(listener);

        //certText.addActionListener(listener);
        certText.addKeyListener(listener);

        certInText.addActionListener(listener);
        certInFile.addActionListener(listener);

        paste.setActionCommand("PASTE");
        paste.addActionListener(listener);


        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("CertInstallCertPane", "title")));


        GridBagUtil.constrain(this, certInFile, 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, certFilename, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.NONE,
                0, 0, DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, certInText, 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this,
                new MultilineLabel(
                resource.getString("CertInstallCertPane",
                "certTextExplain")), 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);


        JScrollPane scrollPane = new JScrollPane(certText,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setBorder(UITools.createLoweredBorder());
        GridBagUtil.constrain(this, scrollPane, 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, paste, 0, ++y, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.NONE, 0,
                0, DIFFERENT_COMPONENT_SPACE, 0);


        GridBagUtil.constrain(this, Box.createVerticalGlue(), 0, ++y,
                1, 1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);


        JLabel _next = new JLabel(resource.getString(null, "clickNextToContinue"));
        GridBagUtil.constrain(this, _next, 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.getContentPane().add("North", new CertInstallCertPane());
     f.setSize(400,400);
     f.show();
     }*/

}

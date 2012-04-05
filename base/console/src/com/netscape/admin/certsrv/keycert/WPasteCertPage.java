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
package com.netscape.admin.certsrv.keycert;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.text.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * This page is to install the certificate in the internal token. The user can
 * import the cert from the file or paste the Base 64 encoded blob in the
 * text area.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WPasteCertPage extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mFileBtn;
    private JRadioButton mBase64Btn;
    private JTextField mFileText;
    private JTextArea mBase64Text;
    private JButton mPaste;
    private JTextArea introLbl;
    private Color mActiveColor;
    private String mCertContent = "";
    private String mCertFilePath = "";
    private static final String PANELNAME = "PASTECERTWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-pastecert-help";

    WPasteCertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WPasteCertPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(wizardInfo.REQUESTTYPE))
            return false;
        setBorder(makeTitledBorder(PANELNAME));
        return true;
    }

    public boolean validatePanel() {
        if (mBase64Btn.isSelected()) {
            mCertContent = mBase64Text.getText().trim();
            if (mCertContent.equals("")) {
                setErrorMessage("B64EEMPTY");
                return false;
            }
        } else if (mFileBtn.isSelected()) {
            mCertFilePath = mFileText.getText().trim();
            if (mCertFilePath.equals("")) {
                setErrorMessage("EMPTYFILE");
                return false;
            }
        }
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        startProgressStatus();
        wizardInfo.addEntry(Constants.PR_PKCS10, mCertContent);
            //cert = CMSAdminUtil.getPureString(mBase64Text.getText().trim());

        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = new NameValuePairs();

        if (mFileBtn.isSelected()) {
            nvps.put(Constants.PR_CERT_FILEPATH, mCertFilePath);
            wizardInfo.setCertFilePath(mCertFilePath);
            wizardInfo.setPKCS10("");
        } else if (mBase64Btn.isSelected()) {
            nvps.put(Constants.PR_PKCS10, mCertContent);
            wizardInfo.setPKCS10(mCertContent);
            wizardInfo.setCertFilePath("");
        }

        try {
            NameValuePairs response = connection.process(
              DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_CERTINFO, wizardInfo.getInstallCertType(), nvps);

            for (String name : response.keySet()) {
                String str = response.get(name);
                wizardInfo.addEntry(name, str);
            }
/*
            for (int i=0; i<response.size(); i++) {
                NameValuePair nvp = response.elementAt(i);
                String name = nvp.getName();
                String str = nvp.getValue();
                wizardInfo.addEntry(name, str);
            }
*/
        } catch (EAdminException e) {
            //showErrorDialog(e.toString());
            setErrorMessage(e.toString());
            endProgressStatus();
            return false;
        }

        endProgressStatus();
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        introLbl = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_INTRO_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(introLbl, gbc);

        mFileBtn = makeJRadioButton("FILE", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mFileBtn, gbc);

        mFileText = makeJTextField(50);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, COMPONENT_SPACE, 0);
        add(mFileText, gbc);
        mActiveColor = mFileText.getBackground();

        mBase64Btn = makeJRadioButton("BASE64", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mBase64Btn, gbc);

        JTextArea desc = createTextArea(mResource.getString(
          "PASTECERTWIZARD_TEXT_DESC_LABEL"));

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,4*COMPONENT_SPACE,0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        mBase64Text = new JTextArea(null, null, 0, 0);
        Font f = new Font("Monospaced", Font.PLAIN, 12);
        if (f != null) mBase64Text.setFont(f);
        JScrollPane scrollPane = new JScrollPane(mBase64Text,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(50, 20));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.fill = gbc.BOTH;
        gbc.gridwidth = gbc.REMAINDER;
        add(scrollPane, gbc);

        mPaste = makeJButton("PASTE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mPaste, gbc);

        JLabel dummy = new JLabel(" ");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.anchor = gbc.NORTHWEST;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        add(dummy, gbc);

        ButtonGroup buttonGrp = new ButtonGroup();
        buttonGrp.add(mFileBtn);
        buttonGrp.add(mBase64Btn);

        enableFields(mFileText, true, mActiveColor);
        enableFields(mBase64Text, false, getBackground());
        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mPaste)) {
            mBase64Text.paste();
        } else if (e.getSource().equals(mFileBtn)) {
            enableFields(mFileText, true, mActiveColor);
            enableFields(mBase64Text, false, getBackground());
        } else if (e.getSource().equals(mBase64Btn)) {
            enableFields(mFileText, false, getBackground());
            enableFields(mBase64Text, true, mActiveColor);
        }
    }

    private void enableFields(JTextComponent comp1, boolean enable, Color color)  {
        comp1.setEnabled(enable);
        comp1.setEditable(enable);
        comp1.setBackground(color);
        CMSAdminUtil.repaintComp(comp1);
    }
}

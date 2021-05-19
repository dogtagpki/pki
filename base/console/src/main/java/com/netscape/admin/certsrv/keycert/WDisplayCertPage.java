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

import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSServerInfo;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;

/**
 * This page is to install the certificate in the internal token. It
 * displays the certificate information.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WDisplayCertPage extends WizardBasePanel implements IWizardPanel {
    private CertSetupWizardInfo wizardInfo;
    private JButton mAdd;
    private static final String PANELNAME = "DISPLAYCERTWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-displaycert-help";
    private JTextArea mTextArea;
    private JTextField mCertNameField;
    private Color mActiveColor;

    WDisplayCertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WDisplayCertPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(CertSetupWizardInfo.REQUESTTYPE))
            return false;

        setBorder(makeTitledBorder(PANELNAME));
        mTextArea.setText(wizardInfo.getCertContent());
        if (wizardInfo.getInstallCertType().equals(Constants.PR_OTHER_CERT)) {
            mCertNameField.setEditable(true);
            mCertNameField.setBackground(mActiveColor);
            mCertNameField.setEnabled(true);
        } else {
            mCertNameField.setEditable(false);
            mCertNameField.setBackground(getBackground());
            mCertNameField.setEnabled(false);
        }

        String certName = wizardInfo.getNickname();
        if (certName != null && !certName.equals(""))
            mCertNameField.setText(certName);

        CMSAdminUtil.repaintComp(mCertNameField);
        return true;
    }

    @Override
    public boolean validatePanel() {
        if (mCertNameField.isEditable()) {
            String str = mCertNameField.getText();
            if (str == null || str.length() == 0) {
                setErrorMessage("EMPTYCERTNAME");
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        AdminConnection connection = wizardInfo.getAdminConnection();
        CMSServerInfo serverInfo = wizardInfo.getServerInfo();
        String certType = wizardInfo.getInstallCertType();
        String pathname = "";
        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            pathname = "prevCACert.txt";
        } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
            pathname = "prevOCSPCert.txt";
        } else if (certType.equals(Constants.PR_RA_SIGNING_CERT)) {
            pathname = "prevRACert.txt";
        } else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
            pathname = "prevKRACert.txt";
        } else if (certType.equals(Constants.PR_SERVER_CERT)) {
            pathname = "prevSSLCert.txt";
        } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
            pathname = "prevSSLCertRadm.txt";
        } else if (certType.equals(Constants.PR_CROSS_CERT)) {
            pathname = "prevCROSSCert.txt";
        } else if (certType.equals(Constants.PR_OTHER_CERT)) {
            pathname = "prevOTHERCert.txt";
        }

        NameValuePairs nvps = new NameValuePairs();
        String cert = wizardInfo.getPKCS10();

        if (cert == null) {
            nvps.put(Constants.PR_CERT_FILEPATH,
                    wizardInfo.getCertFilePath());
        } else {
            nvps.put(Constants.PR_PKCS10, wizardInfo.getPKCS10());
        }

        nvps.put(Constants.PR_NICKNAME, mCertNameField.getText().trim());
        nvps.put("pathname", pathname);
        nvps.put(Constants.PR_SERVER_ROOT, serverInfo.getServerRoot());
        nvps.put(Constants.PR_SERVER_ID, serverInfo.getServerId());

        try {
            connection.modify(
              DestDef.DEST_SERVER_ADMIN,
			      (certType.equals(Constants.PR_CROSS_CERT))?
				      (ScopeDef.SC_IMPORT_CROSS_CERT):(ScopeDef.SC_INSTALL_CERT),
					   certType, nvps);
        } catch (EAdminException ex) {
            showErrorDialog(ex.toString());
            //setErrorMessage(ex.toString());
            wizardInfo.addEntry(Constants.PR_ADD_CERT, Boolean.valueOf(false));
            return false;
        }
        wizardInfo.addEntry(Constants.PR_ADD_CERT, Boolean.valueOf(true));
/*
        CMSAdminUtil.showMessageDialog(mResource, PANELNAME,
          "INSTALL", JOptionPane.INFORMATION_MESSAGE);
*/
        return true;
    }

    @Override
    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    @Override
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label1 = makeJLabel("NAME");
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE);
        add(label1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mCertNameField = new JTextField(30);
        gbc.gridwidth =  GridBagConstraints.REMAINDER;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.weightx=1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(mCertNameField, gbc);
        mActiveColor = mCertNameField.getBackground();

        mCertNameField.setEditable(false);
        mCertNameField.setBackground(getBackground());
        mCertNameField.setEnabled(false);

        CMSAdminUtil.resetGBC(gbc);
        JLabel certLbl = makeJLabel("CONTENT");
        gbc.gridwidth =  GridBagConstraints.REMAINDER;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(certLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mTextArea = new JTextArea("",100,90);
        Font f = new Font("Monospaced", Font.PLAIN, 12);
        if (f != null) mTextArea.setFont(f);
        mTextArea.setEditable(false);
        mTextArea.setBackground(getBackground());
        JScrollPane scrollPanel = new JScrollPane(mTextArea,
                            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPanel.setAlignmentX(LEFT_ALIGNMENT);
        scrollPanel.setAlignmentY(TOP_ALIGNMENT);
        scrollPanel.setBorder(BorderFactory.createLoweredBevelBorder());
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth =  GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.weightx=1.0;
        gbc.weighty=1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(scrollPanel, gbc);

/*
        mAdd = makeJButton("ADD");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        add(mAdd, gbc);
*/

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
        Boolean bool = wizardInfo.isCertAdded();
        if (bool == null)
            wizardInfo.addEntry(Constants.PR_ADD_CERT, Boolean.valueOf(false));
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mAdd)) {

        }
    }
}

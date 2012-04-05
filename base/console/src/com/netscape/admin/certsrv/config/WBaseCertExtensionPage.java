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
package com.netscape.admin.certsrv.config;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.install.InstallWizardInfo;

/**
 * Base class for the Certificate Extension wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
public class WBaseCertExtensionPage extends WizardBasePanel {
    protected JCheckBox mMIMECheckBox, mBasicCheckBox, mExtendedKeyCheckBox;
    protected JCheckBox mAKICheckBox, mSKICheckBox;
    protected JCheckBox mCACheckBox, mCertPathBox, mKeyUsageBox;
    protected JTextField mCertPathText;
    protected JTextArea mMIMEText;
	protected JLabel mCMCLabel;
    protected JButton mPaste;
    protected byte[] mDerByte;
    protected Color mActiveColor;
    protected JCheckBox mSSLClient, mSSLServer, mSSLMail, mObjectSigning, mTimeStamping;
    protected JCheckBox mOCSPSigning, mOCSPNoCheck, mAIACheckBox;
    protected static final String DEFAULT_CERT_LEN = "100";
    protected String mPanelName;
    protected boolean mModified=false;

    public WBaseCertExtensionPage(String panelName) {
        super(panelName);
    }

    public boolean validatePanel() {
        if (mCertPathBox.isSelected()) {
            String str = mCertPathText.getText().trim();
            if (str.equals("")) {
                setErrorMessage("BLANKLEN");
                return false;
            }

            int len = 0;
            try {
                len = Integer.parseInt(str);
            } catch (NumberFormatException e) {
                setErrorMessage("NONINTEGER");
                return false;
            }

            if (len < 0) {
                setErrorMessage("INVALID");
                return false;
            }

        }

        if (mMIMECheckBox.isSelected()) {
            String derString = mMIMEText.getText().trim();
            if (derString.equals("")) {
                setErrorMessage("DERBLANKFIELD");
                return false;
            }
        }

        return true;
    }

    public boolean initializePanel(WizardInfo info) {
        if (!mModified) {
            boolean basicConstraints = mBasicCheckBox.isSelected();
            boolean extendedKey = mExtendedKeyCheckBox.isSelected();
            boolean derExt = mMIMECheckBox.isSelected();

            if (basicConstraints)
                enableBasicConstraints(basicConstraints, mActiveColor);
            else
                enableBasicConstraints(basicConstraints, getBackground());

            enableExtendedKey(extendedKey);

            if (derExt)
                enableMIMEExt(derExt, mActiveColor);
            else
                enableMIMEExt(derExt, getBackground());
        }

		if (info instanceof InstallWizardInfo) {
			InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
			// If signed by self, no request will be generated
			// check if a signing cert installed, make cmc note invisible
			String type = wizardInfo.getCertType();
			if ((type.equals(Constants.PR_KRA_TRANSPORT_CERT) &&
				 wizardInfo.isKRACertLocalCA()) ||
				(type.equals(Constants.PR_SERVER_CERT) &&
				 wizardInfo.isSSLCertLocalCA()) ||
				type.equals(Constants.PR_OCSP_SIGNING_CERT) ||
				(type.equals(Constants.PR_CA_SIGNING_CERT) &&
				 wizardInfo.isCACertLocalCA()) ||
				(type.equals(Constants.PR_SERVER_CERT)  ||
				 type.equals(Constants.PR_KRA_TRANSPORT_CERT)) && (
			     (wizardInfo.isCAInstalled() &&
				 wizardInfo.isCACertInstalledDone()) ||
				 (wizardInfo.isRAInstalled() &&
				 wizardInfo.isRACertInstalledDone()) ||
				 (wizardInfo.isKRAInstalled() &&
				 wizardInfo.isKRACertInstalledDone()) ||
				 (wizardInfo.isOCSPInstalled() &&
				 wizardInfo.isOCSPCertInstalledDone()) ) ) {
				mCMCLabel.setVisible(false);
				CMSAdminUtil.repaintComp(mCMCLabel);
			}
		} else {
			mCMCLabel.setVisible(false);
			CMSAdminUtil.repaintComp(mCMCLabel);
		}

        return true;
    }

    protected void enableBasicConstraints(boolean enable, Color color) {
        mCACheckBox.setEnabled(enable);
        mCertPathBox.setEnabled(enable);
        if (enable && !mCertPathBox.isSelected()) {
            enableCertPath(!enable, getBackground());
        } else {
            enableCertPath(enable, color);
        }
        CMSAdminUtil.repaintComp(mCACheckBox);
        CMSAdminUtil.repaintComp(mCertPathText);
    }

    protected void enableCertPath(boolean enable, Color color) {
        mCertPathText.setEnabled(enable);
        mCertPathText.setEditable(enable);
        mCertPathText.setBackground(color);
        CMSAdminUtil.repaintComp(mCertPathBox);
    }

    protected void enableExtendedKey(boolean enable) {
        mSSLClient.setEnabled(enable);
        mSSLServer.setEnabled(enable);
        mSSLMail.setEnabled(enable);
        mObjectSigning.setEnabled(enable);
        mTimeStamping.setEnabled(enable);
        mOCSPSigning.setEnabled(enable);

        CMSAdminUtil.repaintComp(mSSLClient);
        CMSAdminUtil.repaintComp(mSSLServer);
        CMSAdminUtil.repaintComp(mSSLMail);
        CMSAdminUtil.repaintComp(mObjectSigning);
        CMSAdminUtil.repaintComp(mTimeStamping);
        CMSAdminUtil.repaintComp(mOCSPSigning);
    }

    protected void enableMIMEExt(boolean enable, Color color) {
        mMIMEText.setEnabled(enable);
        mMIMEText.setEditable(enable);
        mMIMEText.setBackground(color);
        mPaste.setEnabled(enable);
        CMSAdminUtil.repaintComp(mMIMEText);
        CMSAdminUtil.repaintComp(mPaste);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea desc = createTextArea(mResource.getString(
          mPanelName+"_TEXT_HEADING_LABEL"));
          //"CERTEXTENSIONWIZARD_TEXT_HEADING_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        mBasicCheckBox = makeJCheckBox("BASIC");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(mBasicCheckBox, gbc);

        mCACheckBox = makeJCheckBox("CA");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE, 0,COMPONENT_SPACE);
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(mCACheckBox, gbc);

        JPanel panel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        panel.setLayout(gb1);

        mCertPathBox = makeJCheckBox("CERTPATHLENGTH");
        CMSAdminUtil.resetGBC(gbc);
        gbc.insets = new Insets(0, 0, 0, COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridheight = gbc.REMAINDER;
        panel.add(mCertPathBox, gbc);

        mCertPathText = makeJTextField(10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.insets = new Insets(0,COMPONENT_SPACE, 0, COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        panel.add(mCertPathText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE);
        add(panel, gbc);

/*
        JTextArea dummy = createTextArea(" ", 1, 5);
        CMSAdminUtil.resetGBC(gbc);
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy, gbc);
*/

        mExtendedKeyCheckBox = makeJCheckBox("EXTENDEDKEY");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(mExtendedKeyCheckBox, gbc);

        mSSLClient = makeJCheckBox("SSLCLIENT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE, 0, COMPONENT_SPACE);
        add(mSSLClient, gbc);

        mSSLServer = makeJCheckBox("SSLSERVER");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE, 0, COMPONENT_SPACE);
        add(mSSLServer, gbc);

        mSSLMail = makeJCheckBox("EMAIL");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0,COMPONENT_SPACE, 0, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        add(mSSLMail, gbc);

        mObjectSigning = makeJCheckBox("OBJECTSIGNING");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE, 0, COMPONENT_SPACE);
        add(mObjectSigning, gbc);

        mTimeStamping = makeJCheckBox("TIMESTAMPING");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mTimeStamping, gbc);

        mOCSPSigning = makeJCheckBox("OCSPSIGNING");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0,COMPONENT_SPACE, 0, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        add(mOCSPSigning, gbc);

        mAIACheckBox = makeJCheckBox("AIA");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mAIACheckBox, gbc);

        mAKICheckBox = makeJCheckBox("AKI");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        add(mAKICheckBox, gbc);

        mSKICheckBox = makeJCheckBox("SKI");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mSKICheckBox, gbc);

        mOCSPNoCheck = makeJCheckBox("OCSPNOCHECK");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mOCSPNoCheck, gbc);

        mCMCLabel = new JLabel(mResource.getString(
            mPanelName + "_TEXT_CMC_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mCMCLabel, gbc);

        mKeyUsageBox = makeJCheckBox("KEYUSAGE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mKeyUsageBox, gbc);
        mKeyUsageBox.setSelected(true);

        mMIMECheckBox = makeJCheckBox("MIME");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(mMIMECheckBox, gbc);

        mMIMEText = new JTextArea("", 40, 70);
        JScrollPane scrollPane = new JScrollPane(mMIMEText,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(50, 30));
        //scrollPane.setAlignmentX(LEFT_ALIGNMENT);
        //scrollPane.setAlignmentY(TOP_ALIGNMENT);
        scrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(scrollPane, gbc);
        mActiveColor = mMIMEText.getBackground();

        mPaste = makeJButton("PASTE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        add(mPaste, gbc);

        super.init();
    }

    public void actionPerformed(ActionEvent e) {
        Object source = e.getSource();
        if (source.equals(mPaste)) {
            mMIMEText.paste();
        } else if (source.equals(mBasicCheckBox)) {
            if (mBasicCheckBox.isSelected())
                enableBasicConstraints(true, mActiveColor);
            else
                enableBasicConstraints(false, getBackground());
        } else if (source.equals(mExtendedKeyCheckBox)) {
            if (mExtendedKeyCheckBox.isSelected())
                enableExtendedKey(true);
            else
                enableExtendedKey(false);
        } else if (source.equals(mMIMECheckBox)) {
            if (mMIMECheckBox.isSelected())
                enableMIMEExt(true, mActiveColor);
            else
                enableMIMEExt(false, getBackground());
        } else if (source.equals(mCertPathBox)) {
            if (mCertPathBox.isSelected())
                enableCertPath(true, mActiveColor);
            else
                enableCertPath(false, getBackground());
        }
    }
}

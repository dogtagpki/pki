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
package com.netscape.admin.certsrv.config.install;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;

import org.dogtag.util.cert.CertUtil;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;

/**
 * Generate the certificate request
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
class WIGenKeyCertReqPage extends WizardBasePanel implements IWizardPanel {
    private JTextArea desc;
    private String mPanelName;
    private static final int LINE_COUNT = 76;
    protected String mHelpIndex;
    protected String mTokenName;

    protected JRadioButton mPKCS10;
    protected JRadioButton mCMC;
	protected String mSigningCert = null;

    WIGenKeyCertReqPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        setBorder(makeTitledBorder(mPanelName));

        String str = mResource.getString(mPanelName+"_TEXT_NEWKEY_LABEL");
        desc.setText(str);
		// check subject key identifier to enable cmc or not
		NameValuePairs nvps =
			(NameValuePairs)wizardInfo.get(InstallWizardInfo.ALL_CERT_INFO);
		if (nvps != null) {
			str = nvps.get(Constants.PR_SKI);
			if (str != null && str.equals(ConfigConstants.TRUE)) {
				mCMC.setEnabled(true);
				mCMC.setVisible(true);
				mPKCS10.setVisible(true);
			} else if (str == null || str.equals(ConfigConstants.FALSE)){
				mCMC.setEnabled(false);
				mCMC.setVisible(false);
				mPKCS10.setVisible(false);
			}
			CMSAdminUtil.repaintComp(mCMC);
			CMSAdminUtil.repaintComp(mPKCS10);
		}
		// check if a signing cert installed
		String type = wizardInfo.getCertType();
		if (!mCMC.isEnabled() &&
			(type.equals(Constants.PR_SERVER_CERT) ||
				type.equals(Constants.PR_KRA_TRANSPORT_CERT)) ) {
			if (wizardInfo.isCAInstalled() &&
				wizardInfo.isCACertInstalledDone()) {
				mSigningCert = Constants.PR_CA_SIGNING_CERT;
				mCMC.setEnabled(true);
				mCMC.setVisible(true);
				CMSAdminUtil.repaintComp(mCMC);
				mPKCS10.setVisible(true);
				CMSAdminUtil.repaintComp(mPKCS10);
			} else if (wizardInfo.isRAInstalled() &&
				wizardInfo.isRACertInstalledDone()) {
				mSigningCert = Constants.PR_RA_SIGNING_CERT;
				mCMC.setEnabled(true);
				mCMC.setVisible(true);
				CMSAdminUtil.repaintComp(mCMC);
				mPKCS10.setVisible(true);
				CMSAdminUtil.repaintComp(mPKCS10);
			} else if (wizardInfo.isKRAInstalled() &&
				wizardInfo.isKRACertInstalledDone()) {
				mSigningCert = Constants.PR_KRA_TRANSPORT_CERT;
				mCMC.setEnabled(true);
				mCMC.setVisible(true);
				CMSAdminUtil.repaintComp(mCMC);
				mPKCS10.setVisible(true);
				CMSAdminUtil.repaintComp(mPKCS10);
			} else if (wizardInfo.isOCSPInstalled() &&
				wizardInfo.isOCSPCertInstalledDone()) {
				mSigningCert = Constants.PR_OCSP_SIGNING_CERT;
				mCMC.setEnabled(true);
				mCMC.setVisible(true);
				CMSAdminUtil.repaintComp(mCMC);
				mPKCS10.setVisible(true);
				CMSAdminUtil.repaintComp(mPKCS10);
			}
		}

		if (type.equals(Constants.PR_OCSP_SIGNING_CERT)) {
			mCMC.setEnabled(false);
			mCMC.setVisible(false);
			CMSAdminUtil.repaintComp(mCMC);
			mPKCS10.setVisible(false);
			CMSAdminUtil.repaintComp(mPKCS10);
		}

        return true;
    }

    @Override
    public boolean validatePanel() {
        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_CERT_REQUEST;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;

        if (wizardInfo.getSubjectName() == null) {
            setErrorMessage("Subject Name is not available. Please redo all the request generation procedure. ");
            return false;
        }
        rawData = rawData+"&"+Constants.PR_SUBJECT_NAME+"="+wizardInfo.getSubjectName();
        if (mTokenName == null) {
            setErrorMessage("Token Name is not available. Please redo all the request generation procedure. ");
			return false;
		}
        rawData = rawData+"&"+Constants.PR_TOKEN_NAME+"="+mTokenName;
		if (wizardInfo.getKeyLength() == null) {
            setErrorMessage("Key Length is not available. Please redo all the request generation procedure. ");
			return false;
		}
        rawData = rawData+"&"+Constants.PR_KEY_LENGTH+"="+wizardInfo.getKeyLength();
		if (wizardInfo.getKeyType() == null) {
            setErrorMessage("Key Type is not available. Please redo all the request generation procedure. ");
			return false;
		}
        rawData = rawData+"&"+Constants.PR_KEY_TYPE+"="+wizardInfo.getKeyType();
        if (wizardInfo.getCertType() == null) {
            setErrorMessage("CertType is not available. Please redo all the request generation procedure. ");
			return false;
		}
        rawData = rawData+"&"+Constants.PR_CERTIFICATE_TYPE+"="+wizardInfo.getCertType();

        NameValuePairs nvps = wizardInfo.getAllCertInfo();//extensions
        if (nvps != null)  {
            for (String name : nvps.keySet()) {
                String value = nvps.get(name);
			    if (name != null && value != null)
                    rawData = rawData+"&"+name+"="+value;
            }
        }

		if (mSigningCert != null) {
            rawData = rawData+"&"+"signing_cert="+mSigningCert;
		}

		if (mPKCS10.isSelected()) {
            rawData = rawData+"&"+wizardInfo.getCertType()+ConfigConstants.PR_REQUEST_FORMAT+
              "="+ConfigConstants.PR_REQUEST_PKCS10;
		} else if (mCMC.isSelected()) {
            rawData = rawData+"&"+wizardInfo.getCertType()+ConfigConstants.PR_REQUEST_FORMAT+"="+ConfigConstants.PR_REQUEST_CMC;
		}

        startProgressStatus();
        //CMSMessageBox dlg = new CMSMessageBox(mAdminFrame, "CGITASK", "CREATEREQ");
        boolean ready = send(rawData, wizardInfo);
        if (ready) {
            String pkcs = wizardInfo.getCertRequest();
            wizardInfo.setCertRequest(reformat(pkcs));
        }
        //dlg.setVisible(false);
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage();
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  mPanelName+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(str);
        }

        return ready;
    }

    private String reformat(String pkcs) {
        int beginIndex = CertUtil.CERT_NEW_REQUEST_HEADER.length();
        int endIndex = CertUtil.CERT_NEW_REQUEST_FOOTER.length();
        int totalLen = pkcs.length();
        String content = pkcs.substring(beginIndex, totalLen-endIndex);
        String result = CertUtil.CERT_NEW_REQUEST_HEADER + "\n";
        int index = 0;
        while (content.length() >= LINE_COUNT) {
            result = result+content.substring(0, LINE_COUNT)+"\n";
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0) {
            result = result + content + "\n" + CertUtil.CERT_NEW_REQUEST_FOOTER;
        } else {
            result = result + CertUtil.CERT_NEW_REQUEST_FOOTER;
        }

        return result;
    }

    @Override
    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    @Override
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

/*
        desc = new JTextArea(2, 80);
        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
*/
        desc = createTextArea("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc, gbc);

        mPKCS10 = makeJRadioButton("PKCS10", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mPKCS10, gbc);

        mCMC = makeJRadioButton("CMC", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mCMC, gbc);

        ButtonGroup group = new ButtonGroup();
        group.add(mCMC);
        group.add(mPKCS10);

        CMSAdminUtil.resetGBC(gbc);
        JLabel d1 = new JLabel(" ");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(d1, gbc);

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}

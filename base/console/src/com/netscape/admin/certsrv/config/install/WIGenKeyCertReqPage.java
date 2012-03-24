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

import java.awt.*;
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;

/**
 * Generate the certificate request
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIGenKeyCertReqPage extends WizardBasePanel implements IWizardPanel {
    private JTextArea desc;
    private String mPanelName;
    private static final String CERTREQ_BEGIN_HEADING = 
      "-----BEGIN NEW CERTIFICATE REQUEST-----";
    private static final String CERTREQ_END_HEADING = 
      "-----END NEW CERTIFICATE REQUEST-----";
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

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        setBorder(makeTitledBorder(mPanelName));

        String str = mResource.getString(mPanelName+"_TEXT_NEWKEY_LABEL");
        desc.setText(str);
		// check subject key identifier to enable cmc or not
		NameValuePairs nvps =
			(NameValuePairs)wizardInfo.get(wizardInfo.ALL_CERT_INFO);
		if (nvps != null) {
			str = (String)nvps.getValue(Constants.PR_SKI);
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

    public boolean validatePanel() {
        return true;
    }

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
            for (int i=0; i<nvps.size(); i++) {
                NameValuePair nvp = (NameValuePair)nvps.elementAt(i);

			    if (nvp.getName()!= null && nvp.getValue()!= null)
                    rawData = rawData+"&"+nvp.getName()+"="+nvp.getValue();
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
        int beginIndex = CERTREQ_BEGIN_HEADING.length();
        int endIndex = CERTREQ_END_HEADING.length();
        int totalLen = pkcs.length();
        String content = pkcs.substring(beginIndex, totalLen-endIndex);   
        String result = CERTREQ_BEGIN_HEADING+"\n";
        int index = 0;
        while (content.length() >= LINE_COUNT) {
            result = result+content.substring(0, LINE_COUNT)+"\n";
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0) {
            result = result+content+"\n"+CERTREQ_END_HEADING;
        } else {
            result = result+CERTREQ_END_HEADING;
        }

        return result;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

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
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        mPKCS10 = makeJRadioButton("PKCS10", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mPKCS10, gbc);

        mCMC = makeJRadioButton("CMC", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mCMC, gbc);

        ButtonGroup group = new ButtonGroup();
        group.add(mCMC);
        group.add(mPKCS10);
     
        CMSAdminUtil.resetGBC(gbc);
        JLabel d1 = new JLabel(" ");
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridheight = gbc.REMAINDER;
        gbc.gridwidth = gbc.REMAINDER;
        add(d1, gbc);
        
        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}

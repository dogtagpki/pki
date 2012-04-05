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
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * This page is to install the certificate in the internal token. It
 * displays the certificate information.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIDisplayCertPage extends WizardBasePanel implements IWizardPanel {
    private JTextArea mTextArea;
    private JTextField mCertNameField;
    protected String mPanelName;
    protected String mHelpIndex;

    WIDisplayCertPage(String panelName) {
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
        String content = wizardInfo.getCertContent();
        String certOrder = wizardInfo.getCertOrder();
        String str = reformat(content, certOrder);
        mTextArea.setText(str);
        mCertNameField.setEditable(false);
        mCertNameField.setBackground(getBackground());
	String tokenName = null;
	String certType = wizardInfo.getCertType();
	if (certType != null) {
	  if (certType.equalsIgnoreCase(Constants.PR_CA_SIGNING_CERT)) {
		  tokenName = wizardInfo.getCATokenName();
	  } else if (certType.equalsIgnoreCase(Constants.PR_RA_SIGNING_CERT)) {
		  tokenName = wizardInfo.getRATokenName();
	  } else if (certType.equalsIgnoreCase(Constants.PR_OCSP_SIGNING_CERT)) {
		  tokenName = wizardInfo.getOCSPTokenName();
	  } else if (certType.equalsIgnoreCase(Constants.PR_KRA_TRANSPORT_CERT)) {
		  tokenName = wizardInfo.getKRATokenName();
	  } else if (certType.equalsIgnoreCase(Constants.PR_SERVER_CERT)) {
		  tokenName = wizardInfo.getSSLTokenName();
	  } else {
		  Debug.println("WIDisplayCertPage: unrecognized certType: "+
					certType);
	  }
	}
	if ((tokenName != null) &&
		!(tokenName.equalsIgnoreCase(Constants.PR_INTERNAL_TOKEN_NAME))) {
		Debug.println("tokenName="+tokenName);
        	mCertNameField.setText(tokenName+":"+wizardInfo.getNickname());
	} else {
		Debug.println("tokenName=null");
        	mCertNameField.setText(wizardInfo.getNickname());
	}
        return true;
    }

    private String reformat(String content, String certOrder) {
        StringBuffer buffer = new StringBuffer(content);
        StringTokenizer tokenizer = new StringTokenizer(certOrder, ":");
        int len = 0;
        while (tokenizer.hasMoreTokens()) {
            String str = (String)tokenizer.nextToken();
            int index = len+Integer.parseInt(str);
            if (index >= buffer.length())
                break;
            buffer.insert(index, "\n");
            len = index+1;
        }
        return buffer.toString();
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_INSTALL_CERT;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        String val = wizardInfo.getPKCS10();
        if (val == null) {
            rawData = rawData+"&"+Constants.PR_CERT_FILEPATH+"="+
              wizardInfo.getCertFilePath();
        } else {
            rawData = rawData+"&"+Constants.PR_PKCS10+"="+
              wizardInfo.getPKCS10();
        }
        rawData = rawData+"&"+Constants.PR_CERTIFICATE_TYPE+"="+wizardInfo.getCertType();
        rawData = rawData+"&"+Constants.PR_NICKNAME+"="+wizardInfo.getNickname();
        if (wizardInfo.getInternalDBPasswd() != null)
            rawData = rawData+"&"+ConfigConstants.PR_DB_PWD+"="+wizardInfo.getInternalDBPasswd();

        startProgressStatus();
        boolean ready = send(rawData, wizardInfo);
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

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label1 = makeJLabel("NAME");
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE);
        add(label1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mCertNameField = new JTextField(30);
        gbc.gridwidth =  gbc.REMAINDER;
        gbc.anchor = gbc.WEST;
        gbc.weightx=1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(mCertNameField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel certLbl = makeJLabel("CONTENT");
        gbc.gridwidth =  gbc.REMAINDER;
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(certLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mTextArea = new JTextArea("",100,90);
        mTextArea.setEditable(false);
        mTextArea.setBackground(getBackground());
        JScrollPane scrollPanel = new JScrollPane(mTextArea,
                            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPanel.setAlignmentX(LEFT_ALIGNMENT);
        scrollPanel.setAlignmentY(TOP_ALIGNMENT);
        scrollPanel.setBorder(BorderFactory.createLoweredBevelBorder());
        gbc.fill = gbc.BOTH;
        gbc.gridwidth =  gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx=1.0;
        gbc.weighty=1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(scrollPanel, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}

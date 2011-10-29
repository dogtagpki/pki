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
import java.io.*;
import java.util.*;
import javax.swing.*;
import javax.swing.text.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;

/**
 * This page is to install the certificate in the internal token. The user can 
 * import the cert from the file, paste the Base 64 encoded blob in the 
 * text area or get the cert from the CMS where the request was sent.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIPasteCertPage extends WizardBasePanel implements IWizardPanel {
	static private int transId = 1;
    private JRadioButton mFileBtn;
    private JRadioButton mBase64Btn;
    private JTextField mFileText;
    private JTextArea mBase64Text;
    private JButton mPaste;
    private String mCertContent = "";
    private String mCertFilePath = "";
    protected String mPanelName;
    protected String mHelpIndex;
    protected Color mActiveColor;
    protected JTextArea introLbl;
    
    protected JTextField mHostText, mPortText, mRIDText;
    protected JLabel mHostLbl, mPortLbl, mRIDLbl;
    protected String mHost, mPort, mRID;
    protected JLabel mSSLText;
    protected JCheckBox mSSL; // ssl or not
    protected JLabel mQueryText;
    protected JRadioButton mQueryBtn;    

    public static final int MAX_PORT = 65535;
    public static final int MIN_PORT = 1;

    WIPasteCertPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mQueryBtn.isSelected())
            enableFields(true, mActiveColor);
        else
            enableFields(false, getBackground());

		String host = wizardInfo.getCMHost();
		if (host != null && !host.equals(""))
			mHostText.setText(host);
		String port = wizardInfo.getCMEEPort();
		if (port != null && !port.equals(""))
			mPortText.setText(port);
		
		String portType = wizardInfo.getCMEEType();
		if (portType != null && portType.equals("http"))
			mSSL.setSelected(false);

		String rid = wizardInfo.getRequestID();
		if (rid != null && !rid.equals(""))
			mRIDText.setText(rid);

        setBorder(makeTitledBorder(mPanelName));
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
        } else if (mQueryBtn.isSelected()) {
			mHost = mHostText.getText().trim();
			mPort = mPortText.getText().trim();
			mRID = mRIDText.getText().trim();

			if (mRID.equals("")) {
				setErrorMessage("BLANKRID");
				return false;
			}
			try {
				int ridnumber = Integer.parseInt(mRID);
			} catch (NumberFormatException e) {
				setErrorMessage("INVALIDRID");
				return false;
			}

			if (mHost.equals("")) {
				setErrorMessage("BLANKHOST");
				return false;
			}
			if (mPort.equals("")) {
				setErrorMessage("BLANKPORT");
				return false;
			}

			try {
				int portnumber = Integer.parseInt(mPort);
				if (portnumber < MIN_PORT || portnumber > MAX_PORT) {
					setErrorMessage("OUTOFRANGE");
					return false;
				}
			} catch (NumberFormatException e) {
				setErrorMessage("INVALIDPORT");
				return false;
			}
			return true;
		}
		return true;

	}

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_GET_CERT_CONTENT;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_READ;
		String reqType = wizardInfo.getCertType();
        rawData = rawData+"&"+Constants.PR_CERTIFICATE_TYPE+"="+reqType;
        if (mFileBtn.isSelected()) {
            rawData = rawData+"&"+Constants.PR_CERT_FILEPATH+"="+mCertFilePath;
            wizardInfo.setCertFilePath(mCertFilePath);
            wizardInfo.setPKCS10("");
        } else if (mBase64Btn.isSelected()) {
            rawData = rawData+"&"+Constants.PR_PKCS10+"="+mCertContent;
			//xxx It's not pkcs10, it's certificate.
            wizardInfo.setPKCS10(mCertContent);
            wizardInfo.setCertFilePath("");
        } else if (mQueryBtn.isSelected()) {
			if (mRID != null && !mRID.equals(""))
				wizardInfo.setRequestID(mRID);
			if (mHost != null && !mHost.equals(""))
				wizardInfo.setCMHost(mHost);
			if (mPort != null && !mPort.equals(""))
				wizardInfo.setCMEEPort(mPort);   
			if (mSSL.isSelected())
				wizardInfo.setCMEEType("https");
			else
				wizardInfo.setCMEEType("http");

            String rawData1 = "importCert=true";
            rawData1=rawData1+"&"+"requestId="+mRID;
/*
			CMSImportCert importCertCgi = new CMSImportCert();
			importCertCgi.initialize(wizardInfo);
			Hashtable data1 = new Hashtable();
			data1.put("importCert", "true");
			data1.put("requestId", mRID);
*/
			 
			startProgressStatus();
			boolean ready = send(mHost, Integer.parseInt(mPort), "/checkRequest",
              rawData1, wizardInfo);
        
			endProgressStatus();

			if (!ready) {
				String str = getErrorMessage();
				if (str.equals(""))
					setErrorMessage("Server Error");
				else
					setErrorMessage(str);
				return ready;
			}
			String certS= wizardInfo.getPKCS10();
			// Break the long single line:header,64 byte lines,trailer
			// Assuming this is the only format we generate.
			String CERT_NEW_HEADER = "-----BEGIN CERTIFICATE-----";
			String CERT_NEW_TRAILER = "-----END CERTIFICATE-----";
			String str = CERT_NEW_HEADER + "\n";
			int len = certS.length();
			for (int i = 0; i < len; i=i+64){
				if (i+64 < len)
					str = str + certS.substring(i,i+64) +"\n";
				else
					str = str + certS.substring(i,len) +"\n";
		    }
			str = str + CERT_NEW_TRAILER;
			certS = str;
            rawData = rawData+"&"+Constants.PR_PKCS10+"="+certS;
            wizardInfo.setPKCS10(certS);
            wizardInfo.setCertFilePath("");
        }

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

        introLbl = createTextArea(mResource.getString(
          mPanelName+"_LABEL_INTRO_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
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

        mBase64Text = new JTextArea(null, null, 6, 10);
        JScrollPane scrollPane = new JScrollPane(mBase64Text, 
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(30, 50));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.5;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, COMPONENT_SPACE);
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

        mQueryBtn = makeJRadioButton("QUERY", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mQueryBtn, gbc);

        mQueryText = new JLabel(mResource.getString(
            mPanelName + "_TEXT_QUERY_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mQueryText, gbc);

        mHostLbl = makeJLabel("HOST");
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mHostLbl, gbc);

        mHostText = makeJTextField(23);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mHostText, gbc);
        mActiveColor = mHostText.getBackground();

        mPortLbl = makeJLabel("PORT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mPortLbl, gbc);

        mPortText = makeJTextField(23);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mPortText, gbc);

        mSSLText = new JLabel(mResource.getString(
            mPanelName+"_TEXT_SSL_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        //gbc.gridwidth = gbc.REMAINDER;
        add(mSSLText, gbc);

        mSSL = makeJCheckBox("SSL", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mSSL, gbc);

        mRIDLbl = makeJLabel("RID");
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mRIDLbl, gbc);

        mRIDText = makeJTextField(23);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mRIDText, gbc);

        JLabel label = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(label, gbc);
		
        ButtonGroup buttonGrp = new ButtonGroup();
        buttonGrp.add(mFileBtn);
        buttonGrp.add(mBase64Btn);
        buttonGrp.add(mQueryBtn);

        enableFields(mFileText, true, mActiveColor);
        enableFields(mBase64Text, false, getBackground());
		enableFields(false,getBackground());

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
            enableFields(false, getBackground());
        } else if (e.getSource().equals(mBase64Btn)) {
            enableFields(mFileText, false, getBackground());
            enableFields(mBase64Text, true, mActiveColor);
            enableFields(false, getBackground());
        } else if (e.getSource().equals(mQueryBtn)) {
            enableFields(mFileText, false, getBackground());
            enableFields(mBase64Text, false, getBackground());
            enableFields(true, mActiveColor);
        }
    }

    private void enableFields(JTextComponent comp1, boolean enable, Color color) {
        comp1.setEnabled(enable);
        comp1.setEditable(enable);
        comp1.setBackground(color);
        CMSAdminUtil.repaintComp(comp1);
    }

    protected void enableFields(boolean enabled, Color color) {
        mQueryText.setEnabled(enabled);
        //mQueryText.setEditable(enabled);
        CMSAdminUtil.repaintComp(mQueryText);
        mHostLbl.setEnabled(enabled);
        mPortLbl.setEnabled(enabled);
        mRIDLbl.setEnabled(enabled);
        mHostText.setEnabled(enabled);
        mHostText.setEditable(enabled);
        mHostText.setBackground(color);
        mPortText.setEnabled(enabled);
        mPortText.setEditable(enabled);
        mPortText.setBackground(color);
        mRIDText.setEnabled(enabled);
        mRIDText.setEditable(enabled);
        mRIDText.setBackground(color);
        CMSAdminUtil.repaintComp(mHostLbl);
        CMSAdminUtil.repaintComp(mHostText);
        CMSAdminUtil.repaintComp(mPortLbl);
        CMSAdminUtil.repaintComp(mPortText);
        CMSAdminUtil.repaintComp(mRIDLbl);
        CMSAdminUtil.repaintComp(mRIDText);
		mSSLText.setEnabled(enabled);
		//mSSLText.setEditable(enabled);
        CMSAdminUtil.repaintComp(mSSLText);
		mSSL.setEnabled(enabled);
		//mSSL.setEditable(enabled);
		//mSSL.setBackground(color);
        CMSAdminUtil.repaintComp(mSSL);

    }
}
